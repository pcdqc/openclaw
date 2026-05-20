import { normalizeLowercaseStringOrEmpty } from "../shared/string-coerce.js";
import {
  hasSudoEnvAssignmentsBeforeCarriedCommand,
  hasSudoShellStartupContextBeforeCarriedCommand,
  isEnvAssignmentToken,
  resolveCarrierCommandArgv,
} from "./command-carriers.js";
import {
  MAX_DISPATCH_WRAPPER_DEPTH,
  hasDispatchEnvManipulation,
  unwrapKnownDispatchWrapperInvocation,
} from "./dispatch-wrapper-resolution.js";
import { normalizeExecutableToken } from "./exec-wrapper-tokens.js";
import { resolvePosixInlineCommandMatch } from "./posix-shell-options.js";
import {
  POWERSHELL_COMMAND_TEXT_OPTIONS,
  isPowerShellOptionToken,
  powerShellOptionConsumesNextArg,
} from "./powershell-options.js";
import {
  POWERSHELL_INLINE_COMMAND_FLAGS,
  resolveInlineCommandMatch,
} from "./shell-inline-command.js";

const POSIX_SHELL_WRAPPER_NAMES = ["ash", "bash", "dash", "fish", "ksh", "sh", "zsh"] as const;
const WINDOWS_CMD_WRAPPER_NAMES = ["cmd"] as const;
const POWERSHELL_WRAPPER_NAMES = ["powershell", "pwsh"] as const;
const SHELL_MULTIPLEXER_WRAPPER_NAMES = ["busybox", "toybox"] as const;

function withWindowsExeAliases(names: readonly string[]): string[] {
  const expanded = new Set<string>();
  for (const name of names) {
    expanded.add(name);
    expanded.add(`${name}.exe`);
  }
  return Array.from(expanded);
}

export const POSIX_SHELL_WRAPPERS = new Set(POSIX_SHELL_WRAPPER_NAMES);
export const POWERSHELL_WRAPPERS = new Set(withWindowsExeAliases(POWERSHELL_WRAPPER_NAMES));

const POSIX_SHELL_WRAPPER_CANONICAL = new Set<string>(POSIX_SHELL_WRAPPER_NAMES);
const WINDOWS_CMD_WRAPPER_CANONICAL = new Set<string>(WINDOWS_CMD_WRAPPER_NAMES);
const POWERSHELL_WRAPPER_CANONICAL = new Set<string>(POWERSHELL_WRAPPER_NAMES);
const SHELL_MULTIPLEXER_WRAPPER_CANONICAL = new Set<string>(SHELL_MULTIPLEXER_WRAPPER_NAMES);
const SHELL_WRAPPER_CANONICAL = new Set<string>([
  ...POSIX_SHELL_WRAPPER_NAMES,
  ...WINDOWS_CMD_WRAPPER_NAMES,
  ...POWERSHELL_WRAPPER_NAMES,
]);

type ShellWrapperKind = "posix" | "cmd" | "powershell";

type ShellWrapperSpec = {
  kind: ShellWrapperKind;
  names: ReadonlySet<string>;
};

const SHELL_WRAPPER_SPECS: ReadonlyArray<ShellWrapperSpec> = [
  { kind: "posix", names: POSIX_SHELL_WRAPPER_CANONICAL },
  { kind: "cmd", names: WINDOWS_CMD_WRAPPER_CANONICAL },
  { kind: "powershell", names: POWERSHELL_WRAPPER_CANONICAL },
];

type ShellWrapperCommand = {
  isWrapper: boolean;
  command: string | null;
};

type ShellWrapperCandidate<TState> = {
  argv: string[];
  token0: string;
  state: TState;
};

function resolveShellWrapperCandidate<TState>(params: {
  argv: string[];
  depth: number;
  state: TState;
  onDispatchUnwrap?: (state: TState, wrappedArgv: string[]) => TState;
}): ShellWrapperCandidate<TState> | null {
  if (!isWithinDispatchClassificationDepth(params.depth)) {
    return null;
  }

  const token0 = params.argv[0]?.trim();
  if (!token0) {
    return null;
  }

  const dispatchUnwrap = unwrapKnownDispatchWrapperInvocation(params.argv);
  if (dispatchUnwrap.kind === "blocked") {
    return null;
  }
  if (dispatchUnwrap.kind === "unwrapped") {
    return resolveShellWrapperCandidate({
      ...params,
      argv: dispatchUnwrap.argv,
      depth: params.depth + 1,
      state: params.onDispatchUnwrap?.(params.state, params.argv) ?? params.state,
    });
  }

  const shellMultiplexerUnwrap = unwrapKnownShellMultiplexerInvocation(params.argv);
  if (shellMultiplexerUnwrap.kind === "blocked") {
    return null;
  }
  if (shellMultiplexerUnwrap.kind === "unwrapped") {
    return resolveShellWrapperCandidate({
      ...params,
      argv: shellMultiplexerUnwrap.argv,
      depth: params.depth + 1,
    });
  }

  return { argv: params.argv, token0, state: params.state };
}

function resolveShellWrapperSpecAndArgvInternal(
  argv: string[],
  depth: number,
): { argv: string[]; wrapper: ShellWrapperSpec; payload: string } | null {
  const candidate = resolveShellWrapperCandidate({ argv, depth, state: null });
  if (!candidate) {
    return null;
  }

  const wrapper = findShellWrapperSpec(normalizeExecutableToken(candidate.token0));
  if (!wrapper) {
    return null;
  }

  const payload = extractShellWrapperPayload(candidate.argv, wrapper);
  if (!payload) {
    return null;
  }

  return { argv: candidate.argv, wrapper, payload };
}

function isWithinDispatchClassificationDepth(depth: number): boolean {
  return depth <= MAX_DISPATCH_WRAPPER_DEPTH;
}

export function isShellWrapperExecutable(token: string): boolean {
  return SHELL_WRAPPER_CANONICAL.has(normalizeExecutableToken(token));
}

function isShellWrapperInvocationInternal(argv: string[], depth: number): boolean {
  const candidate = resolveShellWrapperCandidate({ argv, depth, state: null });
  return candidate ? isShellWrapperExecutable(candidate.token0) : false;
}

export function isShellWrapperInvocation(argv: string[]): boolean {
  return isShellWrapperInvocationInternal(argv, 0);
}

function normalizeRawCommand(rawCommand?: string | null): string | null {
  const trimmed = rawCommand?.trim() ?? "";
  return trimmed.length > 0 ? trimmed : null;
}

function findShellWrapperSpec(baseExecutable: string): ShellWrapperSpec | null {
  for (const spec of SHELL_WRAPPER_SPECS) {
    if (spec.names.has(baseExecutable)) {
      return spec;
    }
  }
  return null;
}

type ShellMultiplexerUnwrapResult =
  | { kind: "not-wrapper" }
  | { kind: "blocked"; wrapper: string }
  | { kind: "unwrapped"; wrapper: string; argv: string[] };

export function unwrapKnownShellMultiplexerInvocation(
  argv: string[],
): ShellMultiplexerUnwrapResult {
  const token0 = argv[0]?.trim();
  if (!token0) {
    return { kind: "not-wrapper" };
  }
  const wrapper = normalizeExecutableToken(token0);
  if (!SHELL_MULTIPLEXER_WRAPPER_CANONICAL.has(wrapper)) {
    return { kind: "not-wrapper" };
  }

  let appletIndex = 1;
  if (argv[appletIndex]?.trim() === "--") {
    appletIndex += 1;
  }
  const applet = argv[appletIndex]?.trim();
  if (!applet || !isShellWrapperExecutable(applet)) {
    return { kind: "blocked", wrapper };
  }

  const unwrapped = argv.slice(appletIndex);
  if (unwrapped.length === 0) {
    return { kind: "blocked", wrapper };
  }
  return { kind: "unwrapped", wrapper, argv: unwrapped };
}

function extractPosixShellInlineCommand(argv: string[]): string | null {
  return resolvePosixInlineCommandMatch(argv).command;
}

function extractCmdInlineCommand(argv: string[]): string | null {
  const idx = argv.findIndex((item) => {
    const token = normalizeLowercaseStringOrEmpty(item);
    return token === "/c" || token === "/k";
  });
  if (idx === -1) {
    return null;
  }
  const tail = argv.slice(idx + 1);
  if (tail.length === 0) {
    return null;
  }
  const cmd = tail.join(" ").trim();
  return cmd.length > 0 ? cmd : null;
}

function extractPowerShellInlineCommand(argv: string[]): string | null {
  const match = resolveInlineCommandMatch(argv, POWERSHELL_INLINE_COMMAND_FLAGS, {
    isOptionToken: isPowerShellOptionToken,
    optionConsumesNextArg: powerShellOptionConsumesNextArg,
    stopAtFirstOperand: true,
  });
  if (match.command === null || match.valueTokenIndex === null) {
    return null;
  }

  const valueToken = argv[match.valueTokenIndex]?.trim() ?? "";
  const equalsIndex = valueToken.indexOf("=");
  if (
    equalsIndex > 0 &&
    POWERSHELL_COMMAND_TEXT_OPTIONS.has(
      normalizeLowercaseStringOrEmpty(valueToken.slice(0, equalsIndex)),
    )
  ) {
    return [match.command, ...argv.slice(match.valueTokenIndex + 1)]
      .map((part) => part.trim())
      .filter((part) => part.length > 0)
      .join(" ");
  }

  const flagToken = argv[match.valueTokenIndex - 1]?.trim() ?? "";
  if (POWERSHELL_COMMAND_TEXT_OPTIONS.has(normalizeLowercaseStringOrEmpty(flagToken))) {
    return argv
      .slice(match.valueTokenIndex)
      .map((part) => part.trim())
      .filter((part) => part.length > 0)
      .join(" ");
  }
  return match.command;
}

function extractInlineCommandByFlags(
  argv: string[],
  flags: ReadonlySet<string>,
  options: Parameters<typeof resolveInlineCommandMatch>[2] = {},
): string | null {
  return resolveInlineCommandMatch(argv, flags, options).command;
}

function extractShellWrapperPayload(argv: string[], spec: ShellWrapperSpec): string | null {
  switch (spec.kind) {
    case "posix":
      return extractPosixShellInlineCommand(argv);
    case "cmd":
      return extractCmdInlineCommand(argv);
    case "powershell":
      return extractPowerShellInlineCommand(argv);
  }
  throw new Error("Unsupported shell wrapper kind");
}

function hasEnvManipulationBeforeShellWrapperInternal(
  argv: string[],
  depth: number,
  envManipulationSeen: boolean,
): boolean {
  const candidate = resolveShellWrapperCandidate({
    argv,
    depth,
    state: envManipulationSeen,
    onDispatchUnwrap: (state, wrappedArgv) => state || hasDispatchEnvManipulation(wrappedArgv),
  });
  if (!candidate) {
    return false;
  }

  const wrapper = findShellWrapperSpec(normalizeExecutableToken(candidate.token0));
  if (!wrapper) {
    return false;
  }
  const payload = extractShellWrapperPayload(candidate.argv, wrapper);
  if (!payload) {
    return false;
  }
  return candidate.state;
}

export function hasEnvManipulationBeforeShellWrapper(argv: string[]): boolean {
  return hasEnvManipulationBeforeShellWrapperInternal(argv, 0, false);
}

export function hasEnvManipulationBeforeShellWrapperInvocation(argv: string[]): boolean {
  const resolved = resolveShellWrapperInvocationThroughCarriersInternal(
    argv,
    0,
    false,
    false,
    false,
    undefined,
    new Set(),
  );
  return Boolean(resolved?.envManipulationSeen || resolved?.argv0ManipulationSeen);
}

export function hasShellAssignmentPrefixBeforeShellWrapperInvocation(
  argv: readonly string[],
): boolean {
  let commandIndex = 0;
  while (commandIndex < argv.length && isEnvAssignmentToken(argv[commandIndex] ?? "")) {
    commandIndex += 1;
  }
  if (commandIndex === 0 || commandIndex >= argv.length) {
    return false;
  }
  return (
    resolveShellWrapperInvocationThroughCarriersInternal(
      argv.slice(commandIndex),
      0,
      false,
      false,
      false,
      undefined,
      new Set(),
    ) !== null
  );
}

function extractShellWrapperCommandInternal(
  argv: string[],
  rawCommand: string | null,
  depth: number,
): ShellWrapperCommand {
  const resolved = resolveShellWrapperSpecAndArgvInternal(argv, depth);
  if (!resolved) {
    return { isWrapper: false, command: null };
  }

  return { isWrapper: true, command: rawCommand ?? resolved.payload };
}

export function resolveShellWrapperTransportArgv(argv: string[]): string[] | null {
  return resolveShellWrapperSpecAndArgvInternal(argv, 0)?.argv ?? null;
}

export function resolveShellWrapperArgv(argv: string[]): string[] | null {
  const candidate = resolveShellWrapperCandidate({ argv, depth: 0, state: null });
  return candidate && isShellWrapperExecutable(candidate.token0) ? candidate.argv : null;
}

type ShellWrapperInvocationThroughCarriers = {
  argv: string[];
  envManipulationSeen: boolean;
  argv0ManipulationSeen: boolean;
  policyBlocked: boolean;
  blockedWrapper?: string;
};

function argvKey(argv: readonly string[]): string {
  return argv.join("\0");
}

function resolveNonEnvCarrierCommandArgv(argv: string[], depth: number): string[] | null {
  if (normalizeExecutableToken(argv[0] ?? "") === "env") {
    return null;
  }
  return resolveCarrierCommandArgv(argv, depth, { includeExec: true });
}

function execInvocationChangesShellContext(argv: readonly string[]): boolean {
  if (normalizeExecutableToken(argv[0] ?? "") !== "exec") {
    return false;
  }
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index] ?? "";
    if (token === "--" || !token.startsWith("-")) {
      return false;
    }
    if (!/^-[A-Za-z0-9]/u.test(token)) {
      return false;
    }
    for (let tokenIndex = 1; tokenIndex < token.length; tokenIndex += 1) {
      const flag = token[tokenIndex] ?? "";
      if (flag === "l" || flag === "a") {
        return true;
      }
      if (flag === "c") {
        return true;
      }
      return false;
    }
  }
  return false;
}

function resolveShellWrapperInvocationThroughCarriersInternal(
  argv: readonly string[],
  depth: number,
  envManipulationSeen: boolean,
  argv0ManipulationSeen: boolean,
  policyBlocked: boolean,
  blockedWrapper: string | undefined,
  seenArgv: Set<string>,
): ShellWrapperInvocationThroughCarriers | null {
  const current = [...argv];
  if (!isWithinDispatchClassificationDepth(depth)) {
    return {
      argv: current,
      envManipulationSeen,
      argv0ManipulationSeen,
      policyBlocked: true,
      blockedWrapper: blockedWrapper ?? "carrier-depth",
    };
  }
  const key = argvKey(current);
  if (seenArgv.has(key)) {
    return null;
  }
  seenArgv.add(key);

  const dispatchUnwrap = unwrapKnownDispatchWrapperInvocation(current);
  const nextPolicyBlocked = policyBlocked || dispatchUnwrap.kind === "blocked";
  const nextBlockedWrapper =
    blockedWrapper ?? (dispatchUnwrap.kind === "blocked" ? dispatchUnwrap.wrapper : undefined);
  if (dispatchUnwrap.kind === "unwrapped" && dispatchUnwrap.wrapper === "env") {
    return resolveShellWrapperInvocationThroughCarriersInternal(
      dispatchUnwrap.argv,
      depth + 1,
      envManipulationSeen || hasDispatchEnvManipulation(current),
      argv0ManipulationSeen,
      nextPolicyBlocked,
      nextBlockedWrapper,
      seenArgv,
    );
  }

  const carrierArgv = resolveNonEnvCarrierCommandArgv(current, depth);
  if (carrierArgv && carrierArgv.length > 0) {
    return resolveShellWrapperInvocationThroughCarriersInternal(
      carrierArgv,
      depth + 1,
      envManipulationSeen ||
        hasSudoEnvAssignmentsBeforeCarriedCommand(current) ||
        hasSudoShellStartupContextBeforeCarriedCommand(current),
      argv0ManipulationSeen || execInvocationChangesShellContext(current),
      nextPolicyBlocked,
      nextBlockedWrapper,
      seenArgv,
    );
  }

  const candidate = resolveShellWrapperCandidate({
    argv: current,
    depth,
    state: envManipulationSeen,
    onDispatchUnwrap: (state, wrappedArgv) => state || hasDispatchEnvManipulation(wrappedArgv),
  });
  if (!candidate) {
    return null;
  }
  if (isShellWrapperExecutable(candidate.token0)) {
    return {
      argv: candidate.argv,
      envManipulationSeen: candidate.state,
      argv0ManipulationSeen,
      policyBlocked: nextPolicyBlocked,
      ...(nextBlockedWrapper ? { blockedWrapper: nextBlockedWrapper } : {}),
    };
  }

  const carriedArgv = resolveNonEnvCarrierCommandArgv(candidate.argv, depth);
  if (!carriedArgv || carriedArgv.length === 0) {
    return null;
  }
  return resolveShellWrapperInvocationThroughCarriersInternal(
    carriedArgv,
    depth + 1,
    candidate.state ||
      hasSudoEnvAssignmentsBeforeCarriedCommand(candidate.argv) ||
      hasSudoShellStartupContextBeforeCarriedCommand(candidate.argv),
    argv0ManipulationSeen || execInvocationChangesShellContext(candidate.argv),
    nextPolicyBlocked,
    nextBlockedWrapper,
    seenArgv,
  );
}

export function resolveShellWrapperArgvThroughCarriers(argv: readonly string[]): string[] | null {
  const resolved = resolveShellWrapperInvocationThroughCarriersInternal(
    argv,
    0,
    false,
    false,
    false,
    undefined,
    new Set(),
  );
  return resolved && !resolved.policyBlocked ? resolved.argv : null;
}

export function hasPolicyBlockedCarrierBeforeShellWrapperInvocation(
  argv: readonly string[],
): boolean {
  return (
    resolveShellWrapperInvocationThroughCarriersInternal(
      argv,
      0,
      false,
      false,
      false,
      undefined,
      new Set(),
    )?.policyBlocked === true
  );
}

export function extractShellWrapperInlineCommand(argv: string[]): string | null {
  const extracted = extractShellWrapperCommandInternal(argv, null, 0);
  return extracted.isWrapper ? extracted.command : null;
}

export function extractShellWrapperInlineCommandThroughCarriers(
  argv: readonly string[],
): string | null {
  const transportArgv = resolveShellWrapperArgvThroughCarriers(argv);
  return transportArgv ? extractShellWrapperInlineCommand(transportArgv) : null;
}

export function extractShellWrapperCommand(
  argv: string[],
  rawCommand?: string | null,
): ShellWrapperCommand {
  return extractShellWrapperCommandInternal(argv, normalizeRawCommand(rawCommand), 0);
}
