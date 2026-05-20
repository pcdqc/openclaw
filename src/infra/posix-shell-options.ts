import { normalizeExecutableToken } from "./exec-wrapper-tokens.js";

const POSIX_LONG_INLINE_COMMAND_OPTIONS = new Set(["--command"]);
const POSIX_LONG_STARTUP_OPTIONS = new Set([
  "--init-file",
  "--login",
  "--rcfile",
  "--startup-file",
  "--startup-script",
]);
const POSIX_LONG_OPTIONS_WITH_VALUE = new Set(["--init-file", "--rcfile", "--startup-script"]);
const POSIX_SHORT_OPTIONS_WITH_VALUE = new Set(["o", "O"]);
const ZSH_DISABLE_STARTUP_OPTIONS = new Set(["--no-rcs"]);

function splitLongOptionName(token: string): string {
  return token.split("=", 1)[0] ?? token;
}

function readZshShortFlags(token: string): string {
  if (
    (!token.startsWith("-") && !token.startsWith("+")) ||
    token.startsWith("--") ||
    token.startsWith("++") ||
    token === "-" ||
    token === "+"
  ) {
    return "";
  }
  return token.slice(1);
}

function updateZshRcsState(params: {
  argv: readonly string[];
  index: number;
  rcsEnabled: boolean;
}): { rcsEnabled: boolean; consumedNextArg: boolean } {
  const token = params.argv[params.index]?.trim() ?? "";
  const optionName = splitLongOptionName(token);
  const optionNameLower = optionName.toLowerCase();
  const tokenLower = token.toLowerCase();
  if (ZSH_DISABLE_STARTUP_OPTIONS.has(optionName)) {
    return { rcsEnabled: false, consumedNextArg: false };
  }
  if (optionNameLower === "--rcs") {
    return { rcsEnabled: true, consumedNextArg: false };
  }
  if (tokenLower === "-o=rcs" || optionNameLower === "-orcs") {
    return { rcsEnabled: true, consumedNextArg: false };
  }
  if (tokenLower === "+o=rcs" || optionNameLower === "+orcs") {
    return { rcsEnabled: false, consumedNextArg: false };
  }
  if (tokenLower === "-o=norcs" || optionNameLower === "-onorcs") {
    return { rcsEnabled: false, consumedNextArg: false };
  }
  if (tokenLower === "+o=norcs" || optionNameLower === "+onorcs") {
    return { rcsEnabled: true, consumedNextArg: false };
  }
  if (optionNameLower === "-o" || optionNameLower === "+o") {
    const optionValue = params.argv[params.index + 1]?.trim().toLowerCase() ?? "";
    if (optionValue === "rcs") {
      return { rcsEnabled: optionNameLower === "-o", consumedNextArg: true };
    }
    if (optionValue === "norcs") {
      return { rcsEnabled: optionNameLower === "+o", consumedNextArg: true };
    }
    return { rcsEnabled: params.rcsEnabled, consumedNextArg: true };
  }
  const flags = readZshShortFlags(token);
  if (token.startsWith("-") && flags.includes("f")) {
    return { rcsEnabled: false, consumedNextArg: false };
  }
  if (token.startsWith("+") && flags.includes("f")) {
    return { rcsEnabled: true, consumedNextArg: false };
  }
  return { rcsEnabled: params.rcsEnabled, consumedNextArg: false };
}

function readPosixShortOptionScan(token: string): {
  hasInlineCommandFlag: boolean;
  hasStartupOption: boolean;
  consumesNextArg: boolean;
} | null {
  if (
    (!token.startsWith("-") && !token.startsWith("+")) ||
    token.startsWith("--") ||
    token.startsWith("++") ||
    token === "-" ||
    token === "+"
  ) {
    return null;
  }

  const flags = token.slice(1);
  let hasInlineCommandFlag = false;
  let hasStartupOption = false;
  let consumesNextArg = false;
  for (let index = 0; index < flags.length; index += 1) {
    const flag = flags[index] ?? "";
    if (token.startsWith("-") && flag === "c") {
      hasInlineCommandFlag = true;
      continue;
    }
    if (token.startsWith("-") && (flag === "i" || flag === "l")) {
      hasStartupOption = true;
      continue;
    }
    if (POSIX_SHORT_OPTIONS_WITH_VALUE.has(flag)) {
      consumesNextArg = true;
      continue;
    }
  }

  return { hasInlineCommandFlag, hasStartupOption, consumesNextArg };
}

export function posixShellShortOptionConsumesNextArg(token: string): boolean {
  return readPosixShortOptionScan(token)?.consumesNextArg ?? false;
}

export function resolvePosixInlineCommandMatch(argv: readonly string[]): {
  command: string | null;
  valueTokenIndex: number | null;
} {
  let sawInlineCommandFlag = false;

  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index]?.trim() ?? "";
    if (!token) {
      continue;
    }
    if (token === "--") {
      if (!sawInlineCommandFlag) {
        return { command: null, valueTokenIndex: null };
      }
      const valueTokenIndex = index + 1 < argv.length ? index + 1 : null;
      const command = argv[index + 1]?.trim();
      return { command: command ? command : null, valueTokenIndex };
    }
    if (!token.startsWith("-") && !token.startsWith("+")) {
      if (!sawInlineCommandFlag) {
        return { command: null, valueTokenIndex: null };
      }
      return { command: token, valueTokenIndex: index };
    }

    if (token.startsWith("--")) {
      const optionName = splitLongOptionName(token);
      if (POSIX_LONG_INLINE_COMMAND_OPTIONS.has(optionName)) {
        const equalsIndex = token.indexOf("=");
        if (equalsIndex > 0) {
          const command = token.slice(equalsIndex + 1).trim();
          return { command: command ? command : null, valueTokenIndex: index };
        }
        sawInlineCommandFlag = true;
        continue;
      }
      if (POSIX_LONG_OPTIONS_WITH_VALUE.has(optionName) && !token.includes("=")) {
        index += 1;
      }
      continue;
    }

    const shortScan = readPosixShortOptionScan(token);
    if (!shortScan) {
      continue;
    }
    if (shortScan.hasInlineCommandFlag) {
      sawInlineCommandFlag = true;
    }
    if (shortScan.consumesNextArg) {
      index += 1;
    }
  }

  return { command: null, valueTokenIndex: null };
}

export function hasPosixShellStartupOptionBeforeCommandOperand(argv: readonly string[]): boolean {
  const executable = normalizeExecutableToken(argv[0] ?? "");
  const tracksZshRcs = executable === "zsh";
  let zshRcsEnabled = tracksZshRcs;
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index]?.trim() ?? "";
    if (!token) {
      continue;
    }
    if (token === "--") {
      return zshRcsEnabled;
    }
    if (!token.startsWith("-") && !token.startsWith("+")) {
      return zshRcsEnabled;
    }

    let zshConsumedNextArg = false;
    if (tracksZshRcs) {
      const zshState = updateZshRcsState({ argv, index, rcsEnabled: zshRcsEnabled });
      zshRcsEnabled = zshState.rcsEnabled;
      zshConsumedNextArg = zshState.consumedNextArg;
    }

    if (token.startsWith("--")) {
      const optionName = splitLongOptionName(token);
      if (POSIX_LONG_STARTUP_OPTIONS.has(optionName)) {
        return true;
      }
      if (POSIX_LONG_INLINE_COMMAND_OPTIONS.has(optionName)) {
        if (token.includes("=")) {
          return zshRcsEnabled;
        }
        continue;
      }
      if (POSIX_LONG_OPTIONS_WITH_VALUE.has(optionName) && !token.includes("=")) {
        index += 1;
      }
      continue;
    }

    const shortScan = readPosixShortOptionScan(token);
    if (!shortScan) {
      continue;
    }
    if (shortScan.hasStartupOption) {
      return true;
    }
    if (shortScan.consumesNextArg || zshConsumedNextArg) {
      index += 1;
    }
  }

  return zshRcsEnabled;
}
