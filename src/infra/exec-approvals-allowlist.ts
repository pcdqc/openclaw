import path from "node:path";
import {
  normalizeLowercaseStringOrEmpty,
  normalizeOptionalLowercaseString,
  normalizeOptionalString,
} from "../shared/string-coerce.js";
import { splitShellArgs } from "../utils/shell-argv.js";
import { isInterpreterLikeAllowlistPattern } from "./command-analysis/inline-eval.js";
import { detectInlineEvalArgv } from "./command-analysis/risks.js";
import {
  hasSudoShellStartupContextBeforeCarriedCommand,
  isEnvAssignmentToken,
  resolveCarrierCommandArgv,
} from "./command-carriers.js";
import { isDispatchWrapperExecutable } from "./dispatch-wrapper-resolution.js";
import {
  analyzeShellCommand,
  isWindowsPlatform,
  matchAllowlist,
  resolveExecutionTargetCandidatePath,
  resolveExecutionTargetResolution,
  resolveCommandResolutionFromArgv,
  resolvePolicyTargetCandidatePath,
  resolvePolicyTargetResolution,
  splitCommandChain,
  splitCommandChainWithOperators,
  type ExecCommandAnalysis,
  type ExecCommandSegment,
  type ExecutableResolution,
} from "./exec-approvals-analysis.js";
import type { ExecAllowlistEntry } from "./exec-approvals.types.js";
import {
  DEFAULT_SAFE_BINS,
  SAFE_BIN_PROFILES,
  type SafeBinProfile,
  validateSafeBinArgv,
} from "./exec-safe-bin-policy.js";
import { isTrustedSafeBinPath } from "./exec-safe-bin-trust.js";
import {
  extractShellWrapperInlineCommand,
  extractShellWrapperInlineCommandThroughCarriers,
  hasEnvManipulationBeforeShellWrapperInvocation,
  hasPolicyBlockedCarrierBeforeShellWrapperInvocation,
  hasShellAssignmentPrefixBeforeShellWrapperInvocation,
  isShellWrapperExecutable,
  normalizeExecutableToken,
  POSIX_SHELL_WRAPPERS,
  POWERSHELL_WRAPPERS,
  resolveShellWrapperArgvThroughCarriers,
} from "./exec-wrapper-resolution.js";
import { resolveExecWrapperTrustPlan } from "./exec-wrapper-trust-plan.js";
import { hasFishStartupCommandOptionBeforeCommandOperand } from "./fish-shell-options.js";
import { expandHomePrefix } from "./home-dir.js";
import {
  hasPosixShellStartupOptionBeforeCommandOperand,
  posixShellShortOptionConsumesNextArg,
  resolvePosixInlineCommandMatch,
} from "./posix-shell-options.js";
import {
  hasPowerShellFileExecutionBeforeCommandPayload,
  isPowerShellDisableProfileOption,
  isPowerShellLoginOption,
  powerShellOptionConsumesNextArg,
} from "./powershell-options.js";
import {
  POWERSHELL_INLINE_COMMAND_FLAGS,
  resolveInlineCommandMatch,
} from "./shell-inline-command.js";

const POSIX_SHELL_WRAPPER_LOOKUP: ReadonlySet<string> = POSIX_SHELL_WRAPPERS;
const CMD_DISABLE_AUTORUN_OPTION = "/d";
const SHELL_ENV_MUTATING_BUILTINS = new Set([
  ".",
  "declare",
  "eval",
  "export",
  "readonly",
  "set",
  "source",
  "typeset",
  "unset",
]);
const SHELL_BUILTIN_ENV_MUTATION_CARRIERS = new Set(["builtin", "command"]);

function hasShellLineContinuation(command: string): boolean {
  return /\\(?:\r\n|\n|\r)/.test(command);
}

export function normalizeSafeBins(entries?: readonly string[]): Set<string> {
  if (!Array.isArray(entries)) {
    return new Set();
  }
  const normalized = entries
    .map((entry) => normalizeLowercaseStringOrEmpty(entry))
    .filter((entry) => entry.length > 0);
  return new Set(normalized);
}

export function resolveSafeBins(entries?: readonly string[] | null): Set<string> {
  if (entries === undefined) {
    return normalizeSafeBins(DEFAULT_SAFE_BINS);
  }
  return normalizeSafeBins(entries ?? []);
}

export function isSafeBinUsage(params: {
  argv: string[];
  resolution: ExecutableResolution | null;
  safeBins: Set<string>;
  platform?: string | null;
  trustedSafeBinDirs?: ReadonlySet<string>;
  safeBinProfiles?: Readonly<Record<string, SafeBinProfile>>;
  isTrustedSafeBinPathFn?: typeof isTrustedSafeBinPath;
}): boolean {
  // Windows host exec uses PowerShell, which has different parsing/expansion rules.
  // Keep safeBins conservative there (require explicit allowlist entries).
  if (isWindowsPlatform(params.platform ?? process.platform)) {
    return false;
  }
  if (params.safeBins.size === 0) {
    return false;
  }
  const resolution = params.resolution;
  const execName = normalizeOptionalLowercaseString(resolution?.executableName);
  if (!execName) {
    return false;
  }
  const matchesSafeBin = params.safeBins.has(execName);
  if (!matchesSafeBin) {
    return false;
  }
  if (!resolution?.resolvedPath) {
    return false;
  }
  const isTrustedPath = params.isTrustedSafeBinPathFn ?? isTrustedSafeBinPath;
  if (
    !isTrustedPath({
      resolvedPath: resolution.resolvedPath,
      trustedDirs: params.trustedSafeBinDirs,
    })
  ) {
    return false;
  }
  const argv = params.argv.slice(1);
  const safeBinProfiles = params.safeBinProfiles ?? SAFE_BIN_PROFILES;
  const profile = safeBinProfiles[execName];
  if (!profile) {
    return false;
  }
  return validateSafeBinArgv(argv, profile, { binName: execName });
}

function isPathScopedExecutableToken(token: string): boolean {
  return token.includes("/") || token.includes("\\");
}

export type ExecAllowlistEvaluation = {
  allowlistSatisfied: boolean;
  allowlistMatches: ExecAllowlistEntry[];
  segmentAllowlistEntries: Array<ExecAllowlistEntry | null>;
  segmentSatisfiedBy: ExecSegmentSatisfiedBy[];
};

export type ExecSegmentSatisfiedBy = "allowlist" | "safeBins" | "skills" | null;
export type SkillBinTrustEntry = {
  name: string;
  resolvedPath: string;
};
type ExecAllowlistContext = {
  allowlist: ExecAllowlistEntry[];
  safeBins: Set<string>;
  safeBinProfiles?: Readonly<Record<string, SafeBinProfile>>;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
  trustedSafeBinDirs?: ReadonlySet<string>;
  skillBins?: readonly SkillBinTrustEntry[];
  autoAllowSkills?: boolean;
};

function pickExecAllowlistContext(params: ExecAllowlistContext): ExecAllowlistContext {
  return {
    allowlist: params.allowlist,
    safeBins: params.safeBins,
    safeBinProfiles: params.safeBinProfiles,
    cwd: params.cwd,
    env: params.env,
    platform: params.platform,
    trustedSafeBinDirs: params.trustedSafeBinDirs,
    skillBins: params.skillBins,
    autoAllowSkills: params.autoAllowSkills,
  };
}

function normalizeSkillBinName(value: string | undefined): string | null {
  const trimmed = normalizeOptionalLowercaseString(value);
  return trimmed && trimmed.length > 0 ? trimmed : null;
}

function normalizeSkillBinResolvedPath(value: string | undefined): string | null {
  const trimmed = normalizeOptionalString(value);
  if (!trimmed) {
    return null;
  }
  const resolved = path.resolve(trimmed);
  if (process.platform === "win32") {
    return normalizeLowercaseStringOrEmpty(resolved.replace(/\\/g, "/"));
  }
  return resolved;
}

function buildSkillBinTrustIndex(
  entries: readonly SkillBinTrustEntry[] | undefined,
): Map<string, Set<string>> {
  const trustByName = new Map<string, Set<string>>();
  if (!entries || entries.length === 0) {
    return trustByName;
  }
  for (const entry of entries) {
    const name = normalizeSkillBinName(entry.name);
    const resolvedPath = normalizeSkillBinResolvedPath(entry.resolvedPath);
    if (!name || !resolvedPath) {
      continue;
    }
    const paths = trustByName.get(name) ?? new Set<string>();
    paths.add(resolvedPath);
    trustByName.set(name, paths);
  }
  return trustByName;
}

function isSkillAutoAllowedSegment(params: {
  segment: ExecCommandSegment;
  allowSkills: boolean;
  skillBinTrust: ReadonlyMap<string, ReadonlySet<string>>;
}): boolean {
  if (!params.allowSkills) {
    return false;
  }
  const resolution = params.segment.resolution;
  const execution = resolveExecutionTargetResolution(resolution);
  if (!execution?.resolvedPath) {
    return false;
  }
  const rawExecutable = execution.rawExecutable?.trim() ?? "";
  if (!rawExecutable || isPathScopedExecutableToken(rawExecutable)) {
    return false;
  }
  const executableName = normalizeSkillBinName(execution.executableName);
  const resolvedPath = normalizeSkillBinResolvedPath(execution.resolvedPath);
  if (!executableName || !resolvedPath) {
    return false;
  }
  return Boolean(params.skillBinTrust.get(executableName)?.has(resolvedPath));
}

const MAX_SHELL_WRAPPER_INLINE_EVAL_DEPTH = 3;

type InlineChainAllowlistEvaluation = {
  matches: ExecAllowlistEntry[];
  satisfiedBy: "allowlist";
};

type SegmentMatchEvaluation = {
  effectiveArgv: string[];
  inlineCommand: string | null;
  match: ExecAllowlistEntry | null;
};

function argvEquals(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isShellParsedSegment(segment: ExecCommandSegment): boolean {
  return segment.source === "shell";
}

function resolveShellWrapperScriptArgv(params: {
  shellScriptCandidatePath: string;
  effectiveArgv: string[];
  cwd?: string;
}): string[] {
  const scriptBase = normalizeLowercaseStringOrEmpty(
    path.basename(params.shellScriptCandidatePath),
  );
  const cwdBase = params.cwd && params.cwd.trim() ? params.cwd.trim() : process.cwd();
  const resolveArgPath = (a: string): string => (path.isAbsolute(a) ? a : path.resolve(cwdBase, a));
  let idx = params.effectiveArgv.findIndex(
    (a) => resolveArgPath(a) === params.shellScriptCandidatePath,
  );
  if (idx === -1) {
    idx = params.effectiveArgv.findIndex(
      (a) => normalizeLowercaseStringOrEmpty(path.basename(a)) === scriptBase,
    );
  }
  const scriptArgs = idx !== -1 ? params.effectiveArgv.slice(idx + 1) : [];
  return [params.shellScriptCandidatePath, ...scriptArgs];
}

function resolveSegmentAllowlistMatch(params: {
  segment: ExecCommandSegment;
  context: ExecAllowlistContext;
}): SegmentMatchEvaluation {
  const effectiveArgv =
    params.segment.resolution?.effectiveArgv && params.segment.resolution.effectiveArgv.length > 0
      ? params.segment.resolution.effectiveArgv
      : params.segment.argv;
  const allowlistSegment =
    effectiveArgv === params.segment.argv
      ? params.segment
      : { ...params.segment, argv: effectiveArgv };
  if (
    segmentMayMutateShellEnvironment(allowlistSegment) ||
    blocksShellPayloadAllowlist(allowlistSegment.argv) ||
    carrierChainBlocksShellPayloadAllowlist(allowlistSegment.argv)
  ) {
    return { effectiveArgv, inlineCommand: null, match: null };
  }
  const carrierShellArgv = isShellParsedSegment(allowlistSegment)
    ? resolveShellWrapperArgvThroughCarriers(allowlistSegment.argv)
    : null;
  const carrierShellSegment =
    carrierShellArgv && !argvEquals(carrierShellArgv, allowlistSegment.argv)
      ? {
          ...allowlistSegment,
          argv: carrierShellArgv,
          resolution: resolveCommandResolutionFromArgv(
            carrierShellArgv,
            params.context.cwd,
            params.context.env,
          ),
        }
      : null;
  const shellAllowlistSegment = carrierShellSegment ?? allowlistSegment;
  const executableResolution = resolvePolicyTargetResolution(params.segment.resolution);
  const candidatePath = resolvePolicyTargetCandidatePath(
    params.segment.resolution,
    params.context.cwd,
  );
  const candidateResolution =
    candidatePath && executableResolution
      ? { ...executableResolution, resolvedPath: candidatePath }
      : executableResolution;
  const inlineCommand = carrierShellSegment
    ? extractShellWrapperInlineCommand(carrierShellSegment.argv)
    : extractShellWrapperInlineCommand(allowlistSegment.argv);
  const isPositionalCarrierInvocation =
    inlineCommand !== null && isDirectShellPositionalCarrierInvocation(inlineCommand);
  const executableMatch =
    isPositionalCarrierInvocation || carrierShellSegment
      ? null
      : matchAllowlist(
          params.context.allowlist,
          candidateResolution,
          effectiveArgv,
          params.context.platform,
        );
  const shellPositionalArgvCandidatePath = resolveShellWrapperPositionalArgvCandidatePath({
    segment: shellAllowlistSegment,
    cwd: params.context.cwd,
    env: params.context.env,
  });
  const shellPositionalArgvMatch = shellPositionalArgvCandidatePath
    ? matchAllowlist(
        params.context.allowlist,
        {
          rawExecutable: shellPositionalArgvCandidatePath,
          resolvedPath: shellPositionalArgvCandidatePath,
          executableName: path.basename(shellPositionalArgvCandidatePath),
        },
        undefined,
        params.context.platform,
      )
    : null;
  const shellScriptCandidatePath =
    inlineCommand === null
      ? resolveShellWrapperScriptCandidatePath({
          segment: shellAllowlistSegment,
          cwd: params.context.cwd,
        })
      : undefined;
  const shellScriptArgv = shellScriptCandidatePath
    ? resolveShellWrapperScriptArgv({
        shellScriptCandidatePath,
        effectiveArgv: shellAllowlistSegment.argv,
        cwd: params.context.cwd,
      })
    : null;
  const shellScriptMatch =
    shellScriptCandidatePath && shellScriptArgv
      ? matchAllowlist(
          params.context.allowlist,
          {
            rawExecutable: shellScriptCandidatePath,
            resolvedPath: shellScriptCandidatePath,
            executableName: path.basename(shellScriptCandidatePath),
          },
          shellScriptArgv,
          params.context.platform,
        )
      : null;
  return {
    effectiveArgv,
    inlineCommand,
    match: executableMatch ?? shellPositionalArgvMatch ?? shellScriptMatch,
  };
}

function resolveSegmentSatisfaction(params: {
  match: ExecAllowlistEntry | null;
  segment: ExecCommandSegment;
  effectiveArgv: string[];
  context: ExecAllowlistContext;
  allowSkills: boolean;
  skillBinTrust: ReadonlyMap<string, ReadonlySet<string>>;
}): ExecSegmentSatisfiedBy {
  if (params.match) {
    return "allowlist";
  }
  const safe = isSafeBinUsage({
    argv: params.effectiveArgv,
    resolution: resolveExecutionTargetResolution(params.segment.resolution),
    safeBins: params.context.safeBins,
    safeBinProfiles: params.context.safeBinProfiles,
    platform: params.context.platform,
    trustedSafeBinDirs: params.context.trustedSafeBinDirs,
  });
  if (safe) {
    return "safeBins";
  }
  const skillAllow = isSkillAutoAllowedSegment({
    segment: params.segment,
    allowSkills: params.allowSkills,
    skillBinTrust: params.skillBinTrust,
  });
  return skillAllow ? "skills" : null;
}

function resolveInlineChainFallback(params: {
  by: ExecSegmentSatisfiedBy;
  inlineCommand: string | null;
  context: ExecAllowlistContext;
  inlineDepth: number;
}): InlineChainAllowlistEvaluation | null {
  if (params.by !== null || !params.inlineCommand) {
    return null;
  }
  const inlineChainParts = splitCommandChain(params.inlineCommand);
  if (!inlineChainParts || inlineChainParts.length <= 1) {
    return null;
  }
  return evaluateShellWrapperInlineChain({
    inlineCommand: params.inlineCommand,
    context: params.context,
    inlineDepth: params.inlineDepth + 1,
    precomputedChainParts: inlineChainParts,
  });
}

function evaluateShellWrapperInlineChain(params: {
  inlineCommand: string;
  context: ExecAllowlistContext;
  inlineDepth: number;
  precomputedChainParts?: string[];
}): InlineChainAllowlistEvaluation | null {
  if (params.inlineDepth >= MAX_SHELL_WRAPPER_INLINE_EVAL_DEPTH) {
    return null;
  }
  if (isWindowsPlatform(params.context.platform)) {
    return null;
  }
  const chainParts = params.precomputedChainParts ?? splitCommandChain(params.inlineCommand);
  if (!chainParts || chainParts.length <= 1) {
    return null;
  }

  const matches: ExecAllowlistEntry[] = [];
  for (const part of chainParts) {
    const analysis = analyzeShellCommand({
      command: part,
      cwd: params.context.cwd,
      env: params.context.env,
      platform: params.context.platform,
    });
    if (!analysis.ok) {
      return null;
    }
    const result = evaluateSegments(analysis.segments, params.context, params.inlineDepth);
    if (!result.satisfied) {
      return null;
    }
    matches.push(...result.matches);
  }
  return { matches, satisfiedBy: "allowlist" };
}

function evaluateSegments(
  segments: ExecCommandSegment[],
  params: ExecAllowlistContext,
  inlineDepth: number = 0,
): {
  satisfied: boolean;
  matches: ExecAllowlistEntry[];
  segmentAllowlistEntries: Array<ExecAllowlistEntry | null>;
  segmentSatisfiedBy: ExecSegmentSatisfiedBy[];
} {
  const matches: ExecAllowlistEntry[] = [];
  const skillBinTrust = buildSkillBinTrustIndex(params.skillBins);
  const allowSkills = params.autoAllowSkills === true && skillBinTrust.size > 0;
  const segmentAllowlistEntries: Array<ExecAllowlistEntry | null> = [];
  const segmentSatisfiedBy: ExecSegmentSatisfiedBy[] = [];

  const satisfied = segments.every((segment) => {
    if (segment.resolution?.policyBlocked === true) {
      segmentAllowlistEntries.push(null);
      segmentSatisfiedBy.push(null);
      return false;
    }
    const { effectiveArgv, inlineCommand, match } = resolveSegmentAllowlistMatch({
      segment,
      context: params,
    });
    if (match) {
      matches.push(match);
    }
    segmentAllowlistEntries.push(match ?? null);
    const by = resolveSegmentSatisfaction({
      match,
      segment,
      effectiveArgv,
      context: params,
      allowSkills,
      skillBinTrust,
    });
    const inlineResult = resolveInlineChainFallback({
      by,
      inlineCommand,
      context: params,
      inlineDepth,
    });
    if (inlineResult) {
      matches.push(...inlineResult.matches);
      // Keep per-segment metadata aligned with segments: one satisfaction marker
      // for this wrapper segment, even when the inline payload has multiple parts.
      segmentSatisfiedBy.push(inlineResult.satisfiedBy);
      return true;
    }
    segmentSatisfiedBy.push(by);
    return Boolean(by);
  });

  return { satisfied, matches, segmentAllowlistEntries, segmentSatisfiedBy };
}

function resolveAnalysisSegmentGroups(analysis: ExecCommandAnalysis): ExecCommandSegment[][] {
  if (analysis.chains) {
    return analysis.chains;
  }
  return [analysis.segments];
}

export function evaluateExecAllowlist(
  params: {
    analysis: ExecCommandAnalysis;
  } & ExecAllowlistContext,
): ExecAllowlistEvaluation {
  const allowlistMatches: ExecAllowlistEntry[] = [];
  const segmentAllowlistEntries: Array<ExecAllowlistEntry | null> = [];
  const segmentSatisfiedBy: ExecSegmentSatisfiedBy[] = [];
  if (!params.analysis.ok || params.analysis.segments.length === 0) {
    return {
      allowlistSatisfied: false,
      allowlistMatches,
      segmentAllowlistEntries,
      segmentSatisfiedBy,
    };
  }

  const allowlistContext = pickExecAllowlistContext(params);
  const hasChains = Boolean(params.analysis.chains);
  for (const group of resolveAnalysisSegmentGroups(params.analysis)) {
    const result = evaluateSegments(group, allowlistContext);
    if (!result.satisfied) {
      if (!hasChains) {
        return {
          allowlistSatisfied: false,
          allowlistMatches: result.matches,
          segmentAllowlistEntries: result.segmentAllowlistEntries,
          segmentSatisfiedBy: result.segmentSatisfiedBy,
        };
      }
      return {
        allowlistSatisfied: false,
        allowlistMatches: [],
        segmentAllowlistEntries: [],
        segmentSatisfiedBy: [],
      };
    }
    allowlistMatches.push(...result.matches);
    segmentAllowlistEntries.push(...result.segmentAllowlistEntries);
    segmentSatisfiedBy.push(...result.segmentSatisfiedBy);
  }
  return {
    allowlistSatisfied: true,
    allowlistMatches,
    segmentAllowlistEntries,
    segmentSatisfiedBy,
  };
}

export type ExecAllowlistAnalysis = {
  analysisOk: boolean;
  allowlistSatisfied: boolean;
  allowlistMatches: ExecAllowlistEntry[];
  exactCommandDurableApprovalAllowed: boolean;
  segments: ExecCommandSegment[];
  segmentAllowlistEntries: Array<ExecAllowlistEntry | null>;
  segmentSatisfiedBy: ExecSegmentSatisfiedBy[];
};

function hasSegmentExecutableMatch(
  segment: ExecCommandSegment,
  predicate: (token: string) => boolean,
): boolean {
  const execution = resolveExecutionTargetResolution(segment.resolution);
  const candidates = [execution?.executableName, execution?.rawExecutable, segment.argv[0]];
  for (const candidate of candidates) {
    if (typeof candidate !== "string") {
      continue;
    }
    const trimmed = candidate.trim();
    if (!trimmed) {
      continue;
    }
    if (predicate(trimmed)) {
      return true;
    }
  }
  return false;
}

function isShellWrapperSegment(segment: ExecCommandSegment): boolean {
  return hasSegmentExecutableMatch(segment, isShellWrapperExecutable);
}

const SHELL_WRAPPER_OPTIONS_WITH_VALUE = new Set(["-c", "--command", "-o", "-O", "+o", "+O"]);

const SHELL_WRAPPER_DISQUALIFYING_SCRIPT_OPTIONS = [
  "--rcfile",
  "--init-file",
  "--startup-file",
] as const;

function hasDisqualifyingShellWrapperScriptOption(token: string): boolean {
  return SHELL_WRAPPER_DISQUALIFYING_SCRIPT_OPTIONS.some(
    (option) => token === option || token.startsWith(`${option}=`),
  );
}

function resolveShellWrapperScriptCandidatePath(params: {
  segment: ExecCommandSegment;
  cwd?: string;
}): string | undefined {
  if (!isShellWrapperSegment(params.segment)) {
    return undefined;
  }

  const argv = params.segment.argv;
  if (!Array.isArray(argv) || argv.length < 2) {
    return undefined;
  }

  const wrapperName = normalizeExecutableToken(argv[0] ?? "");
  const isPowerShell = POWERSHELL_WRAPPERS.has(wrapperName);
  if (
    (wrapperName === "fish" && hasFishStartupCommandOptionBeforeCommandOperand(argv)) ||
    (!isPowerShell && hasPosixShellStartupOptionBeforeCommandOperand(argv))
  ) {
    return undefined;
  }

  let idx = 1;
  while (idx < argv.length) {
    const token = argv[idx]?.trim() ?? "";
    if (!token) {
      idx += 1;
      continue;
    }
    if (token === "--") {
      idx += 1;
      break;
    }
    if (token === "-c" || token === "--command") {
      return undefined;
    }
    if (!isPowerShell && /^-[^-]*c[^-]*$/u.test(token)) {
      return undefined;
    }
    if (token === "-s" || (!isPowerShell && /^-[^-]*s[^-]*$/u.test(token))) {
      return undefined;
    }
    if (hasDisqualifyingShellWrapperScriptOption(token)) {
      return undefined;
    }
    if (
      SHELL_WRAPPER_OPTIONS_WITH_VALUE.has(token) ||
      (!isPowerShell && posixShellShortOptionConsumesNextArg(token))
    ) {
      idx += 2;
      continue;
    }
    if (isPowerShell && powerShellOptionConsumesNextArg(token)) {
      idx += 2;
      continue;
    }
    if (token.startsWith("-") || token.startsWith("+")) {
      idx += 1;
      continue;
    }
    break;
  }

  const scriptToken = argv[idx]?.trim();
  if (!scriptToken) {
    return undefined;
  }
  if (path.isAbsolute(scriptToken)) {
    return scriptToken;
  }

  const expanded = scriptToken.startsWith("~") ? expandHomePrefix(scriptToken) : scriptToken;
  const base = params.cwd && params.cwd.trim().length > 0 ? params.cwd : process.cwd();
  return path.resolve(base, expanded);
}

function resolveShellWrapperPositionalArgvCandidatePath(params: {
  segment: ExecCommandSegment;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}): string | undefined {
  if (!isShellWrapperSegment(params.segment)) {
    return undefined;
  }

  const argv = params.segment.argv;
  if (!Array.isArray(argv) || argv.length < 4) {
    return undefined;
  }

  const wrapper = normalizeExecutableToken(argv[0] ?? "");
  if (!["ash", "bash", "dash", "fish", "ksh", "sh", "zsh"].includes(wrapper)) {
    return undefined;
  }
  if (
    (wrapper === "fish" && hasFishStartupCommandOptionBeforeCommandOperand(argv)) ||
    hasPosixShellStartupOptionBeforeCommandOperand(argv)
  ) {
    return undefined;
  }

  const inlineMatch = resolvePosixInlineCommandMatch(argv);
  if (inlineMatch.valueTokenIndex === null || !inlineMatch.command) {
    return undefined;
  }
  if (!isDirectShellPositionalCarrierInvocation(inlineMatch.command)) {
    return undefined;
  }

  const carriedExecutable = argv
    .slice(inlineMatch.valueTokenIndex + 1)
    .map((token) => token.trim())
    .find((token) => token.length > 0);
  if (!carriedExecutable) {
    return undefined;
  }

  const carriedName = normalizeExecutableToken(carriedExecutable);
  if (isDispatchWrapperExecutable(carriedName) || isShellWrapperExecutable(carriedName)) {
    return undefined;
  }

  const resolution = resolveCommandResolutionFromArgv([carriedExecutable], params.cwd, params.env);
  return resolveExecutionTargetCandidatePath(resolution, params.cwd);
}

function isDirectShellPositionalCarrierInvocation(command: string): boolean {
  const trimmed = command.trim();
  if (trimmed.length === 0) {
    return false;
  }

  const shellWhitespace = String.raw`[^\S\r\n]+`;
  const positionalZero = String.raw`(?:\$(?:0|\{0\})|"\$(?:0|\{0\})")`;
  const positionalArg = String.raw`(?:\$(?:[@*]|[1-9]|\{[@*1-9]\})|"\$(?:[@*]|[1-9]|\{[@*1-9]\})")`;
  return new RegExp(
    `^(?:exec${shellWhitespace}(?:--${shellWhitespace})?)?${positionalZero}(?:${shellWhitespace}${positionalArg})*$`,
    "u",
  ).test(trimmed);
}

export type AllowAlwaysPattern = {
  pattern: string;
  argPattern?: string;
};

function escapeRegExpLiteral(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildScriptArgPatternFromArgv(
  argv: string[],
  scriptPath: string,
  cwd?: string,
  platform?: string | null,
): string | undefined {
  if (!isWindowsPlatform(platform ?? process.platform)) {
    return undefined;
  }
  const scriptBase = normalizeLowercaseStringOrEmpty(path.basename(scriptPath));
  const base = cwd && cwd.trim() ? cwd.trim() : process.cwd();
  const resolveArgPath = (arg: string): string =>
    path.isAbsolute(arg) ? arg : path.resolve(base, arg);
  let scriptIdx = argv.findIndex((arg) => resolveArgPath(arg) === scriptPath);
  if (scriptIdx === -1) {
    scriptIdx = argv.findIndex(
      (arg) => normalizeLowercaseStringOrEmpty(path.basename(arg)) === scriptBase,
    );
  }
  const scriptArgs = scriptIdx !== -1 ? argv.slice(scriptIdx + 1) : [];
  const normalized = scriptArgs.map((a) => a.replace(/\//g, "\\"));
  if (normalized.length === 0) {
    return "^\x00\x00$";
  }
  return `^${normalized.map(escapeRegExpLiteral).join("\x00")}\x00$`;
}

function buildArgPatternFromArgv(argv: string[], platform?: string | null): string | undefined {
  if (!isWindowsPlatform(platform ?? process.platform)) {
    return undefined;
  }
  const args = argv.slice(1);
  const normalized = args.map((a) => a.replace(/\//g, "\\"));
  if (normalized.length === 0) {
    return "^\x00\x00$";
  }
  const joined = normalized.join("\x00");
  return `^${escapeRegExpLiteral(joined)}\x00$`;
}

function addAllowAlwaysPattern(
  out: AllowAlwaysPattern[],
  pattern: string,
  argPattern?: string,
): void {
  const exists = out.some(
    (p) => p.pattern === pattern && (p.argPattern ?? undefined) === (argPattern ?? undefined),
  );
  if (!exists) {
    out.push({ pattern, argPattern });
  }
}

function hasShellStartupOptionBeforeCommandOperand(argv: readonly string[]): boolean {
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

function blocksShellPayloadAllowlist(argv: readonly string[]): boolean {
  return (
    hasSudoShellStartupContextBeforeCarriedCommand([...argv]) ||
    hasPolicyBlockedCarrierBeforeShellWrapperInvocation(argv) ||
    hasEnvManipulationBeforeShellWrapperInvocation([...argv]) ||
    hasShellAssignmentPrefixBeforeShellWrapperInvocation(argv) ||
    hasShellStartupOptionBeforeCommandOperand(argv) ||
    hasPowerShellFileExecution(argv)
  );
}

function carrierChainBlocksShellPayloadAllowlist(argv: readonly string[], depth = 0): boolean {
  if (depth >= MAX_SHELL_WRAPPER_INLINE_EVAL_DEPTH) {
    return true;
  }
  const carried = resolveCarrierCommandArgv([...argv], depth, { includeExec: true });
  if (!carried || carried.length === 0) {
    return false;
  }
  if (blocksShellPayloadAllowlist(carried)) {
    return true;
  }
  return carrierChainBlocksShellPayloadAllowlist(carried, depth + 1);
}

function commandTextBlocksExactCommandDurableApproval(command: string): boolean {
  const argv = splitShellArgs(command);
  return argv ? blocksShellPayloadAllowlist(argv) : false;
}

function resolveCommandCarrierTargetIndex(
  argv: readonly string[],
  startIndex: number,
): number | null {
  let idx = startIndex;
  while (idx < argv.length) {
    const token = argv[idx]?.trim() ?? "";
    if (!token) {
      idx += 1;
      continue;
    }
    if (token === "--") {
      return idx + 1 < argv.length ? idx + 1 : null;
    }
    if (!token.startsWith("-") || token === "-") {
      return idx;
    }
    const flags = token.slice(1);
    if (!flags || [...flags].some((flag) => flag !== "p" && flag !== "v" && flag !== "V")) {
      return null;
    }
    if (flags.includes("v") || flags.includes("V")) {
      return null;
    }
    idx += 1;
  }
  return null;
}

function resolveShellEnvironmentMutationArgv(argv: readonly string[]): readonly string[] {
  let current = argv;
  while (current.length > 0) {
    const executable = normalizeExecutableToken(current[0]?.trim() ?? "");
    if (!SHELL_BUILTIN_ENV_MUTATION_CARRIERS.has(executable)) {
      return current;
    }
    if (executable === "builtin") {
      current = current.slice(1);
      continue;
    }
    const targetIndex = resolveCommandCarrierTargetIndex(current, 1);
    if (targetIndex === null) {
      return current;
    }
    current = current.slice(targetIndex);
  }
  return current;
}

function segmentMayMutateShellEnvironment(segment: ExecCommandSegment): boolean {
  const argv = resolveShellEnvironmentMutationArgv(segment.argv);
  const firstToken = argv[0]?.trim() ?? "";
  if (!firstToken) {
    return false;
  }
  if (isEnvAssignmentToken(firstToken)) {
    return true;
  }
  const executable = normalizeExecutableToken(firstToken);
  if (!SHELL_ENV_MUTATING_BUILTINS.has(executable)) {
    return false;
  }
  return argv.slice(1).some((token) => {
    const trimmed = token.trim();
    return trimmed.length > 0 && trimmed !== "--" && !trimmed.startsWith("-");
  });
}

function segmentStartsShellGroup(segment: ExecCommandSegment): boolean {
  const first = segment.argv[0]?.trim();
  return first === "{" || first === "}";
}

function segmentContainsShellWrapper(segment: ExecCommandSegment): boolean {
  return resolveShellWrapperArgvThroughCarriers(segment.argv) !== null;
}

function segmentGroupsHaveEnvironmentMutationBeforeShellWrapper(
  groups: ReadonlyArray<readonly ExecCommandSegment[]>,
): boolean {
  let shellEnvironmentMutated = false;
  for (const segments of groups) {
    if (shellEnvironmentMutated && segments.some(segmentContainsShellWrapper)) {
      return true;
    }
    if (segments.some(segmentMayMutateShellEnvironment)) {
      shellEnvironmentMutated = true;
    }
  }
  return false;
}

function shellChainBlocksExactCommandDurableApproval(
  evaluations: ReadonlyArray<{ analysis: ExecCommandAnalysis }>,
): boolean {
  return segmentGroupsHaveEnvironmentMutationBeforeShellWrapper(
    evaluations.map(({ analysis }) => analysis.segments),
  );
}

type ExactCommandDurableApprovalContext = {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
  depth?: number;
};

function segmentBlocksExactCommandDurableApproval(
  segment: ExecCommandSegment,
  context: ExactCommandDurableApprovalContext,
): boolean {
  const depth = context.depth ?? 0;
  if (depth >= MAX_SHELL_WRAPPER_INLINE_EVAL_DEPTH) {
    return true;
  }
  if (segmentStartsShellGroup(segment)) {
    return true;
  }
  const argv =
    segment.resolution?.effectiveArgv && segment.resolution.effectiveArgv.length > 0
      ? segment.resolution.effectiveArgv
      : segment.argv;
  if (blocksShellPayloadAllowlist(argv)) {
    return true;
  }
  if (carrierChainBlocksShellPayloadAllowlist(argv, depth)) {
    return true;
  }
  const inlineCommand = extractShellWrapperInlineCommandThroughCarriers(argv);
  if (!inlineCommand) {
    return false;
  }
  if (isDirectShellPositionalCarrierInvocation(inlineCommand)) {
    return true;
  }
  const nested = analyzeShellCommand({
    command: inlineCommand,
    cwd: context.cwd,
    env: context.env,
    platform: context.platform,
  });
  if (!nested.ok) {
    return true;
  }
  return analysisBlocksExactCommandDurableApproval(nested, {
    ...context,
    depth: depth + 1,
  });
}

function analysisBlocksExactCommandDurableApproval(
  analysis: ExecCommandAnalysis,
  context: ExactCommandDurableApprovalContext,
): boolean {
  if (
    segmentGroupsHaveEnvironmentMutationBeforeShellWrapper(resolveAnalysisSegmentGroups(analysis))
  ) {
    return true;
  }
  return analysis.segments.some((segment) =>
    segmentBlocksExactCommandDurableApproval(segment, context),
  );
}

export function allowsExactCommandDurableApprovalForSegments(
  segments: readonly ExecCommandSegment[],
  context: ExactCommandDurableApprovalContext = {},
): boolean {
  return !segments.some((segment) => segmentBlocksExactCommandDurableApproval(segment, context));
}

function collectAllowAlwaysPatterns(params: {
  segment: ExecCommandSegment;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
  strictInlineEval?: boolean;
  depth: number;
  out: AllowAlwaysPattern[];
}) {
  if (params.depth >= 3) {
    return;
  }

  const trustPlan = resolveExecWrapperTrustPlan(params.segment.argv);
  if (trustPlan.policyBlocked) {
    return;
  }
  const segment =
    trustPlan.argv === params.segment.argv
      ? params.segment
      : {
          raw: trustPlan.argv.join(" "),
          argv: trustPlan.argv,
          resolution: resolveCommandResolutionFromArgv(trustPlan.argv, params.cwd, params.env),
          source: params.segment.source,
        };
  if (
    segmentMayMutateShellEnvironment(segment) ||
    blocksShellPayloadAllowlist(segment.argv) ||
    carrierChainBlocksShellPayloadAllowlist(segment.argv, params.depth)
  ) {
    return;
  }

  const carrierShellArgv = isShellParsedSegment(segment)
    ? resolveShellWrapperArgvThroughCarriers(segment.argv)
    : null;
  if (carrierShellArgv && !argvEquals(carrierShellArgv, segment.argv)) {
    const carrierInlineCommand = extractShellWrapperInlineCommand(carrierShellArgv);
    const carrierInlineChain = carrierInlineCommand
      ? splitCommandChain(carrierInlineCommand)
      : null;
    if (!carrierInlineChain || carrierInlineChain.length <= 1) {
      return;
    }
    collectAllowAlwaysPatterns({
      segment: {
        raw: carrierShellArgv.join(" "),
        argv: carrierShellArgv,
        resolution: resolveCommandResolutionFromArgv(carrierShellArgv, params.cwd, params.env),
        source: segment.source,
      },
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
      strictInlineEval: params.strictInlineEval,
      depth: params.depth,
      out: params.out,
    });
    return;
  }

  const candidatePath = resolveExecutionTargetCandidatePath(segment.resolution, params.cwd);
  if (!candidatePath) {
    return;
  }
  if (isInterpreterLikeAllowlistPattern(candidatePath)) {
    const effectiveArgv = segment.resolution?.effectiveArgv ?? segment.argv;
    if (params.strictInlineEval !== true || detectInlineEvalArgv(effectiveArgv) !== null) {
      return;
    }
  }
  if (!trustPlan.shellWrapperExecutable) {
    const argPattern = buildArgPatternFromArgv(segment.argv, params.platform);
    addAllowAlwaysPattern(params.out, candidatePath, argPattern);
    return;
  }
  const positionalArgvPath = resolveShellWrapperPositionalArgvCandidatePath({
    segment,
    cwd: params.cwd,
    env: params.env,
  });
  if (positionalArgvPath) {
    addAllowAlwaysPattern(params.out, positionalArgvPath);
    return;
  }
  const isPowerShellFileInvocation =
    POWERSHELL_WRAPPERS.has(normalizeExecutableToken(segment.argv[0] ?? "")) &&
    segment.argv.some((t) => {
      const lower = normalizeLowercaseStringOrEmpty(t);
      return lower === "-file" || lower === "-f";
    }) &&
    !segment.argv.some((t) => {
      const lower = normalizeLowercaseStringOrEmpty(t);
      return lower === "-command" || lower === "-c" || lower === "--command";
    });
  const inlineCommand = isPowerShellFileInvocation
    ? null
    : (trustPlan.shellInlineCommand ?? extractShellWrapperInlineCommand(segment.argv));
  if (!inlineCommand) {
    const scriptPath = resolveShellWrapperScriptCandidatePath({
      segment,
      cwd: params.cwd,
    });
    if (scriptPath) {
      const argPattern = buildScriptArgPatternFromArgv(
        params.segment.argv,
        scriptPath,
        params.cwd,
        params.platform,
      );
      addAllowAlwaysPattern(params.out, scriptPath, argPattern);
    }
    return;
  }
  const nested = analyzeShellCommand({
    command: inlineCommand,
    cwd: params.cwd,
    env: params.env,
    platform: params.platform,
  });
  if (!nested.ok) {
    return;
  }
  if (
    segmentGroupsHaveEnvironmentMutationBeforeShellWrapper(resolveAnalysisSegmentGroups(nested))
  ) {
    return;
  }
  for (const nestedSegment of nested.segments) {
    collectAllowAlwaysPatterns({
      segment: nestedSegment,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
      strictInlineEval: params.strictInlineEval,
      depth: params.depth + 1,
      out: params.out,
    });
  }
}

/**
 * Derive persisted allowlist patterns for an "allow always" decision.
 * When a command is wrapped in a shell (for example `zsh -lc "<cmd>"`),
 * persist the inner executable(s) rather than the shell binary.
 */
export function resolveAllowAlwaysPatternEntries(params: {
  segments: ExecCommandSegment[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
  strictInlineEval?: boolean;
}): AllowAlwaysPattern[] {
  const patterns: AllowAlwaysPattern[] = [];
  if (segmentGroupsHaveEnvironmentMutationBeforeShellWrapper([params.segments])) {
    return patterns;
  }
  for (const segment of params.segments) {
    collectAllowAlwaysPatterns({
      segment,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
      strictInlineEval: params.strictInlineEval,
      depth: 0,
      out: patterns,
    });
  }
  return patterns;
}

export function resolveAllowAlwaysPatterns(params: {
  segments: ExecCommandSegment[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  platform?: string | null;
  strictInlineEval?: boolean;
}): string[] {
  return resolveAllowAlwaysPatternEntries(params).map((pattern) => pattern.pattern);
}

/**
 * Evaluates allowlist for shell commands (including &&, ||, ;) and returns analysis metadata.
 */
export function evaluateShellAllowlist(
  params: {
    command: string;
    env?: NodeJS.ProcessEnv;
  } & ExecAllowlistContext,
): ExecAllowlistAnalysis {
  const allowlistContext = pickExecAllowlistContext(params);
  const commandBlocksExactCommandDurableApproval = commandTextBlocksExactCommandDurableApproval(
    params.command,
  );
  const analysisFailure = (): ExecAllowlistAnalysis => ({
    analysisOk: false,
    allowlistSatisfied: false,
    allowlistMatches: [],
    exactCommandDurableApprovalAllowed: false,
    segments: [],
    segmentAllowlistEntries: [],
    segmentSatisfiedBy: [],
  });

  // Keep allowlist analysis conservative: line-continuation semantics are shell-dependent
  // and can rewrite token boundaries at runtime.
  if (hasShellLineContinuation(params.command)) {
    return analysisFailure();
  }

  const chainParts = isWindowsPlatform(params.platform)
    ? null
    : splitCommandChainWithOperators(params.command);
  if (!chainParts) {
    const analysis = analyzeShellCommand({
      command: params.command,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
    });
    if (!analysis.ok) {
      return analysisFailure();
    }
    const evaluation = evaluateExecAllowlist({ analysis, ...allowlistContext });
    return {
      analysisOk: true,
      allowlistSatisfied:
        evaluation.allowlistSatisfied && !commandBlocksExactCommandDurableApproval,
      allowlistMatches: evaluation.allowlistMatches,
      exactCommandDurableApprovalAllowed:
        allowsExactCommandDurableApprovalForSegments(analysis.segments, {
          cwd: params.cwd,
          env: params.env,
          platform: params.platform,
        }) && !commandBlocksExactCommandDurableApproval,
      segments: analysis.segments,
      segmentAllowlistEntries: evaluation.segmentAllowlistEntries,
      segmentSatisfiedBy: evaluation.segmentSatisfiedBy,
    };
  }

  const chainEvaluations = chainParts.map(({ part }) => {
    const analysis = analyzeShellCommand({
      command: part,
      cwd: params.cwd,
      env: params.env,
      platform: params.platform,
    });
    if (!analysis.ok) {
      return null;
    }
    return {
      analysis,
      evaluation: evaluateExecAllowlist({ analysis, ...allowlistContext }),
    };
  });
  if (chainEvaluations.some((entry) => entry === null)) {
    return analysisFailure();
  }

  const finalizedEvaluations = chainEvaluations as Array<{
    analysis: ExecCommandAnalysis;
    evaluation: ExecAllowlistEvaluation;
  }>;
  const allowlistMatches: ExecAllowlistEntry[] = [];
  const segments: ExecCommandSegment[] = [];
  const segmentAllowlistEntries: Array<ExecAllowlistEntry | null> = [];
  const segmentSatisfiedBy: ExecSegmentSatisfiedBy[] = [];
  const exactCommandDurableApprovalAllowed =
    allowsExactCommandDurableApprovalForSegments(
      finalizedEvaluations.flatMap(({ analysis }) => analysis.segments),
      {
        cwd: params.cwd,
        env: params.env,
        platform: params.platform,
      },
    ) &&
    !commandBlocksExactCommandDurableApproval &&
    !shellChainBlocksExactCommandDurableApproval(finalizedEvaluations);

  for (const [index, { analysis, evaluation }] of finalizedEvaluations.entries()) {
    segments.push(...analysis.segments);
    allowlistMatches.push(...evaluation.allowlistMatches);
    segmentAllowlistEntries.push(...evaluation.segmentAllowlistEntries);
    segmentSatisfiedBy.push(...evaluation.segmentSatisfiedBy);
    if (!evaluation.allowlistSatisfied) {
      return {
        analysisOk: true,
        allowlistSatisfied: false,
        allowlistMatches,
        exactCommandDurableApprovalAllowed,
        segments,
        segmentAllowlistEntries,
        segmentSatisfiedBy,
      };
    }
  }

  return {
    analysisOk: true,
    allowlistSatisfied: !commandBlocksExactCommandDurableApproval,
    allowlistMatches,
    exactCommandDurableApprovalAllowed,
    segments,
    segmentAllowlistEntries,
    segmentSatisfiedBy,
  };
}
