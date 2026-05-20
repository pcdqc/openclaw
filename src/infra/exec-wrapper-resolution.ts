export { basenameLower, normalizeExecutableToken } from "./exec-wrapper-tokens.js";
export {
  extractEnvAssignmentKeysFromDispatchWrappers,
  isDispatchWrapperExecutable,
  resolveDispatchWrapperTrustPlan,
  unwrapDispatchWrappersForResolution,
  unwrapEnvInvocation,
  unwrapKnownDispatchWrapperInvocation,
} from "./dispatch-wrapper-resolution.js";
export {
  extractShellWrapperCommand,
  extractShellWrapperInlineCommand,
  extractShellWrapperInlineCommandThroughCarriers,
  hasEnvManipulationBeforeShellWrapper,
  hasEnvManipulationBeforeShellWrapperInvocation,
  hasPolicyBlockedCarrierBeforeShellWrapperInvocation,
  hasShellAssignmentPrefixBeforeShellWrapperInvocation,
  isShellWrapperExecutable,
  isShellWrapperInvocation,
  POSIX_SHELL_WRAPPERS,
  POWERSHELL_WRAPPERS,
  resolveShellWrapperArgv,
  resolveShellWrapperArgvThroughCarriers,
  resolveShellWrapperTransportArgv,
  unwrapKnownShellMultiplexerInvocation,
} from "./shell-wrapper-resolution.js";
