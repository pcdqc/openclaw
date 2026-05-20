import {
  analyzeArgvCommand,
  allowsExactCommandDurableApprovalForSegments,
  evaluateExecAllowlist,
  evaluateShellAllowlist,
  resolvePlannedSegmentArgv,
  resolveExecApprovals,
  type ExecAllowlistEntry,
  type ExecCommandSegment,
  type ExecSecurity,
  type SkillBinTrustEntry,
} from "../infra/exec-approvals.js";
import { resolveExecSafeBinRuntimePolicy } from "../infra/exec-safe-bin-runtime-policy.js";
import {
  extractShellWrapperInlineCommandThroughCarriers,
  hasEnvManipulationBeforeShellWrapperInvocation,
  hasPolicyBlockedCarrierBeforeShellWrapperInvocation,
  hasShellAssignmentPrefixBeforeShellWrapperInvocation,
  normalizeExecutableToken,
  POSIX_SHELL_WRAPPERS,
  POWERSHELL_WRAPPERS,
  resolveShellWrapperArgvThroughCarriers,
} from "../infra/exec-wrapper-resolution.js";
import { hasFishStartupCommandOptionBeforeCommandOperand } from "../infra/fish-shell-options.js";
import { hasPosixShellStartupOptionBeforeCommandOperand } from "../infra/posix-shell-options.js";
import {
  hasPowerShellFileExecutionBeforeCommandPayload,
  isPowerShellDisableProfileOption,
  isPowerShellLoginOption,
  powerShellOptionConsumesNextArg,
} from "../infra/powershell-options.js";
import {
  POWERSHELL_INLINE_COMMAND_FLAGS,
  resolveInlineCommandMatch,
} from "../infra/shell-inline-command.js";
import type { RunResult } from "./invoke-types.js";

const POSIX_SHELL_WRAPPER_LOOKUP: ReadonlySet<string> = POSIX_SHELL_WRAPPERS;
const CMD_DISABLE_AUTORUN_OPTION = "/d";

type SystemRunAllowlistAnalysis = {
  analysisOk: boolean;
  allowlistMatches: ExecAllowlistEntry[];
  allowlistSatisfied: boolean;
  exactCommandDurableApprovalAllowed: boolean;
  segments: ExecCommandSegment[];
  segmentAllowlistEntries: Array<ExecAllowlistEntry | null>;
};

function hasStartupShellWrapperContext(argv: string[]): boolean {
  const transportArgv = resolveShellWrapperArgvThroughCarriers(argv);
  if (!transportArgv) {
    return false;
  }
  const wrapper = normalizeExecutableToken(transportArgv[0] ?? "");
  if (wrapper === "cmd") {
    return hasCmdStartupContextBeforeInlineCommand(transportArgv);
  }
  if (POWERSHELL_WRAPPERS.has(wrapper)) {
    return hasPowerShellStartupContextBeforeInlineCommand(transportArgv);
  }
  if (wrapper === "fish") {
    return hasFishStartupCommandOptionBeforeCommandOperand(transportArgv);
  }
  return (
    POSIX_SHELL_WRAPPER_LOOKUP.has(wrapper) &&
    hasPosixShellStartupOptionBeforeCommandOperand(transportArgv)
  );
}

function findCmdInlineCommandFlagIndex(argv: readonly string[]): number | null {
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index]?.trim().toLowerCase() ?? "";
    if (token === "/c" || token === "/k") {
      return index;
    }
  }
  return null;
}

function hasCmdStartupContextBeforeInlineCommand(argv: readonly string[]): boolean {
  const inlineCommandFlagIndex = findCmdInlineCommandFlagIndex(argv);
  if (inlineCommandFlagIndex === null) {
    return false;
  }
  for (let index = 1; index < inlineCommandFlagIndex; index += 1) {
    const token = argv[index]?.trim().toLowerCase() ?? "";
    if (token === CMD_DISABLE_AUTORUN_OPTION) {
      return false;
    }
  }
  return true;
}

function shellOptionName(token: string): string {
  return token.split("=", 1)[0] ?? token;
}

function hasPowerShellStartupContextBeforeInlineCommand(argv: readonly string[]): boolean {
  const inlineCommandMatch = resolveInlineCommandMatch([...argv], POWERSHELL_INLINE_COMMAND_FLAGS);
  if (inlineCommandMatch.valueTokenIndex === null) {
    return false;
  }
  const inlineCommandFlagIndex = POWERSHELL_INLINE_COMMAND_FLAGS.has(
    shellOptionName(argv[inlineCommandMatch.valueTokenIndex]?.trim().toLowerCase() ?? ""),
  )
    ? inlineCommandMatch.valueTokenIndex
    : Math.max(1, inlineCommandMatch.valueTokenIndex - 1);
  let profilesDisabled = false;
  let loginShell = false;
  for (let index = 1; index < inlineCommandFlagIndex; index += 1) {
    const token = argv[index]?.trim() ?? "";
    if (isPowerShellLoginOption(token)) {
      loginShell = true;
    } else if (isPowerShellDisableProfileOption(token)) {
      profilesDisabled = true;
    }
    if (powerShellOptionConsumesNextArg(token)) {
      index += 1;
    }
  }
  return loginShell || !profilesDisabled;
}

function hasPowerShellFileExecution(argv: readonly string[]): boolean {
  const transportArgv = resolveShellWrapperArgvThroughCarriers(argv);
  if (!transportArgv) {
    return false;
  }
  const wrapper = normalizeExecutableToken(transportArgv[0] ?? "");
  if (!POWERSHELL_WRAPPERS.has(wrapper)) {
    return false;
  }
  return hasPowerShellFileExecutionBeforeCommandPayload(transportArgv);
}

function blocksShellPayloadAllowlist(argv: string[]): boolean {
  return (
    hasEnvManipulationBeforeShellWrapperInvocation(argv) ||
    hasPolicyBlockedCarrierBeforeShellWrapperInvocation(argv) ||
    hasStartupShellWrapperContext(argv) ||
    hasShellAssignmentPrefixBeforeShellWrapperInvocation(argv) ||
    hasPowerShellFileExecution(argv)
  );
}

function transportShellPayloadMatchesRequest(params: {
  argv: string[];
  shellCommand: string;
}): boolean {
  return (
    extractShellWrapperInlineCommandThroughCarriers(params.argv)?.trim() ===
    params.shellCommand.trim()
  );
}

export function evaluateSystemRunAllowlist(params: {
  shellCommand: string | null;
  argv: string[];
  approvals: ReturnType<typeof resolveExecApprovals>;
  security: ExecSecurity;
  safeBins: ReturnType<typeof resolveExecSafeBinRuntimePolicy>["safeBins"];
  safeBinProfiles: ReturnType<typeof resolveExecSafeBinRuntimePolicy>["safeBinProfiles"];
  trustedSafeBinDirs: ReturnType<typeof resolveExecSafeBinRuntimePolicy>["trustedSafeBinDirs"];
  cwd: string | undefined;
  env: Record<string, string> | undefined;
  skillBins: SkillBinTrustEntry[];
  autoAllowSkills: boolean;
}): SystemRunAllowlistAnalysis {
  if (params.shellCommand) {
    if (
      !transportShellPayloadMatchesRequest({
        argv: params.argv,
        shellCommand: params.shellCommand,
      })
    ) {
      return {
        analysisOk: false,
        allowlistMatches: [],
        allowlistSatisfied: false,
        exactCommandDurableApprovalAllowed: false,
        segments: [],
        segmentAllowlistEntries: [],
      };
    }
    const allowlistEval = evaluateShellAllowlist({
      command: params.shellCommand,
      allowlist: params.approvals.allowlist,
      safeBins: params.safeBins,
      safeBinProfiles: params.safeBinProfiles,
      cwd: params.cwd,
      env: params.env,
      trustedSafeBinDirs: params.trustedSafeBinDirs,
      skillBins: params.skillBins,
      autoAllowSkills: params.autoAllowSkills,
      platform: process.platform,
    });
    const transportBlocksShellPayloadAllowlist = blocksShellPayloadAllowlist(params.argv);
    if (transportBlocksShellPayloadAllowlist) {
      return {
        analysisOk: false,
        allowlistMatches: [],
        allowlistSatisfied: false,
        exactCommandDurableApprovalAllowed: false,
        segments: allowlistEval.segments,
        segmentAllowlistEntries: allowlistEval.segments.map(() => null),
      };
    }
    const transportAnalysis = analyzeArgvCommand({
      argv: params.argv,
      cwd: params.cwd,
      env: params.env,
    });
    const transportAllowsExactCommandDurableApproval =
      transportAnalysis.ok &&
      allowsExactCommandDurableApprovalForSegments(transportAnalysis.segments, {
        cwd: params.cwd,
        env: params.env,
        platform: process.platform,
      });
    return {
      analysisOk: allowlistEval.analysisOk,
      allowlistMatches: allowlistEval.allowlistMatches,
      allowlistSatisfied:
        params.security === "allowlist" && allowlistEval.analysisOk
          ? allowlistEval.allowlistSatisfied
          : false,
      exactCommandDurableApprovalAllowed:
        allowlistEval.exactCommandDurableApprovalAllowed &&
        transportAllowsExactCommandDurableApproval,
      segments: allowlistEval.segments,
      segmentAllowlistEntries: allowlistEval.segmentAllowlistEntries,
    };
  }

  const analysis = analyzeArgvCommand({ argv: params.argv, cwd: params.cwd, env: params.env });
  const allowlistEval = evaluateExecAllowlist({
    analysis,
    allowlist: params.approvals.allowlist,
    safeBins: params.safeBins,
    safeBinProfiles: params.safeBinProfiles,
    cwd: params.cwd,
    trustedSafeBinDirs: params.trustedSafeBinDirs,
    skillBins: params.skillBins,
    autoAllowSkills: params.autoAllowSkills,
  });
  return {
    analysisOk: analysis.ok,
    allowlistMatches: allowlistEval.allowlistMatches,
    allowlistSatisfied:
      params.security === "allowlist" && analysis.ok ? allowlistEval.allowlistSatisfied : false,
    exactCommandDurableApprovalAllowed:
      analysis.ok &&
      allowsExactCommandDurableApprovalForSegments(analysis.segments, {
        cwd: params.cwd,
        env: params.env,
        platform: process.platform,
      }),
    segments: analysis.segments,
    segmentAllowlistEntries: allowlistEval.segmentAllowlistEntries,
  };
}

export function resolvePlannedAllowlistArgv(params: {
  security: ExecSecurity;
  shellCommand: string | null;
  policy: {
    approvedByAsk: boolean;
    analysisOk: boolean;
    allowlistSatisfied: boolean;
  };
  segments: ExecCommandSegment[];
}): string[] | undefined | null {
  if (
    params.security !== "allowlist" ||
    params.policy.approvedByAsk ||
    params.shellCommand ||
    !params.policy.analysisOk ||
    !params.policy.allowlistSatisfied ||
    params.segments.length !== 1
  ) {
    return undefined;
  }
  const plannedAllowlistArgv = resolvePlannedSegmentArgv(params.segments[0]);
  return plannedAllowlistArgv && plannedAllowlistArgv.length > 0 ? plannedAllowlistArgv : null;
}

export function resolveSystemRunExecArgv(params: {
  plannedAllowlistArgv: string[] | undefined;
  argv: string[];
  security: ExecSecurity;
  isWindows: boolean;
  policy: {
    approvedByAsk: boolean;
    analysisOk: boolean;
    allowlistSatisfied: boolean;
  };
  shellCommand: string | null;
  segments: ExecCommandSegment[];
}): string[] {
  let execArgv = params.plannedAllowlistArgv ?? params.argv;
  if (
    params.security === "allowlist" &&
    params.isWindows &&
    !params.policy.approvedByAsk &&
    params.shellCommand &&
    params.policy.analysisOk &&
    params.policy.allowlistSatisfied &&
    params.segments.length === 1 &&
    params.segments[0]?.argv.length > 0
  ) {
    execArgv = params.segments[0].argv;
  }
  return execArgv;
}

export function applyOutputTruncation(result: RunResult): void {
  if (!result.truncated) {
    return;
  }
  const suffix = "... (truncated)";
  if (result.stderr.trim().length > 0) {
    result.stderr = `${result.stderr}\n${suffix}`;
  } else {
    result.stdout = `${result.stdout}\n${suffix}`;
  }
}
