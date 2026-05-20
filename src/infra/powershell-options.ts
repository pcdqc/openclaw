export const POWERSHELL_COMMAND_TEXT_OPTIONS: ReadonlySet<string> = new Set([
  "-c",
  "-command",
  "--command",
]);

export const POWERSHELL_COMMAND_PAYLOAD_OPTIONS: ReadonlySet<string> = new Set([
  ...POWERSHELL_COMMAND_TEXT_OPTIONS,
  "-e",
  "-en",
  "-enc",
  "-encodedcommand",
]);

export const POWERSHELL_DISABLE_PROFILE_OPTIONS: ReadonlySet<string> = new Set([
  "-noprofile",
  "-nop",
  "/noprofile",
  "/nop",
]);

const POWERSHELL_LOGIN_OPTIONS: ReadonlySet<string> = new Set(["-login", "-l", "/login", "/l"]);

const POWERSHELL_OPTIONS_WITH_VALUE: ReadonlySet<string> = new Set([
  "-config",
  "-configurationfile",
  "-configurationname",
  "-custompipename",
  "-ea",
  "-en",
  "-enc",
  "-encodedarguments",
  "-encodedcommand",
  "-ex",
  "-ep",
  "-executionpolicy",
  "-if",
  "-inp",
  "-inputformat",
  "-o",
  "-of",
  "-outputformat",
  "-pscf",
  "-psconsolefile",
  "-settings",
  "-settingsfile",
  "-v",
  "-version",
  "-w",
  "-wd",
  "-wo",
  "-windowstyle",
  "-workingdirectory",
]);

export function powerShellOptionName(token: string): string {
  return token.trim().toLowerCase().split("=", 1)[0] ?? "";
}

export function isPowerShellFileExecutionOption(token: string): boolean {
  const optionName = powerShellOptionName(token);
  if (!optionName.startsWith("-") && !optionName.startsWith("/")) {
    return false;
  }
  const switchName = optionName.replace(/^--?/u, "").replace(/^\//u, "");
  return switchName.length >= 1 && "file".startsWith(switchName);
}

export function powerShellOptionConsumesNextArg(token: string): boolean {
  const trimmed = token.trim();
  return POWERSHELL_OPTIONS_WITH_VALUE.has(powerShellOptionName(trimmed)) && !trimmed.includes("=");
}

export function isPowerShellDisableProfileOption(token: string): boolean {
  return POWERSHELL_DISABLE_PROFILE_OPTIONS.has(powerShellOptionName(token));
}

export function isPowerShellLoginOption(token: string): boolean {
  return POWERSHELL_LOGIN_OPTIONS.has(powerShellOptionName(token));
}

function isKnownPowerShellSlashOption(token: string): boolean {
  const optionName = powerShellOptionName(token);
  return (
    POWERSHELL_DISABLE_PROFILE_OPTIONS.has(optionName) ||
    POWERSHELL_LOGIN_OPTIONS.has(optionName) ||
    isPowerShellFileExecutionOption(token)
  );
}

export function isPowerShellOptionToken(token: string): boolean {
  const optionName = powerShellOptionName(token);
  return optionName.startsWith("-") || isKnownPowerShellSlashOption(token);
}

export function hasPowerShellFileExecutionBeforeCommandPayload(argv: readonly string[]): boolean {
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index]?.trim() ?? "";
    if (!token) {
      continue;
    }
    const optionName = powerShellOptionName(token);
    if (isPowerShellFileExecutionOption(token)) {
      return true;
    }
    if (POWERSHELL_COMMAND_PAYLOAD_OPTIONS.has(optionName)) {
      return false;
    }
    if (optionName === "--") {
      return (argv[index + 1]?.trim() ?? "").length > 0;
    }
    if (powerShellOptionConsumesNextArg(token)) {
      index += 1;
      continue;
    }
    if (optionName.startsWith("-") || isKnownPowerShellSlashOption(token)) {
      continue;
    }
    return true;
  }
  return false;
}
