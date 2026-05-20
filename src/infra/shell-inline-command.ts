import { normalizeLowercaseStringOrEmpty } from "../shared/string-coerce.js";

export const POSIX_INLINE_COMMAND_FLAGS = new Set(["-lc", "-c", "--command"]);
export const POWERSHELL_INLINE_COMMAND_FLAGS = new Set([
  "-c",
  "-command",
  "--command",
  "-f",
  "-file",
  "-en",
  "-encodedcommand",
  "-enc",
  "-e",
]);

const COMBINED_POSIX_VALUE_FLAGS = new Set(["o", "O"]);

function resolveCombinedPosixCommandOperandIndex(token: string, tokenIndex: number): number | null {
  const flags = token.slice(1);
  if (!/^[A-Za-z]+$/u.test(flags)) {
    return null;
  }
  if (!flags.includes("c")) {
    return null;
  }
  let extraValueOperandCount = 0;
  for (const flag of flags.split("")) {
    if (COMBINED_POSIX_VALUE_FLAGS.has(flag)) {
      extraValueOperandCount += 1;
    }
  }
  return tokenIndex + 1 + extraValueOperandCount;
}

export function resolveInlineCommandMatch(
  argv: string[],
  flags: ReadonlySet<string>,
  options: {
    allowCombinedC?: boolean;
    allowPlusOptions?: boolean;
    caseSensitive?: boolean;
    isOptionToken?: (token: string) => boolean;
    optionConsumesNextArg?: (token: string) => boolean;
    stopAtFirstOperand?: boolean;
  } = {},
): { command: string | null; valueTokenIndex: number | null } {
  for (let i = 1; i < argv.length; i += 1) {
    const token = argv[i]?.trim();
    if (!token) {
      continue;
    }
    const flagToken = options.caseSensitive ? token : normalizeLowercaseStringOrEmpty(token);
    if (flagToken === "--") {
      break;
    }
    if (flags.has(flagToken)) {
      const valueTokenIndex = i + 1 < argv.length ? i + 1 : null;
      const command = argv[i + 1]?.trim();
      return { command: command ? command : null, valueTokenIndex };
    }
    if (flagToken.startsWith("--")) {
      const equalsIndex = flagToken.indexOf("=");
      if (equalsIndex > 0 && flags.has(flagToken.slice(0, equalsIndex))) {
        const command = token.slice(equalsIndex + 1).trim();
        return { command: command ? command : null, valueTokenIndex: i };
      }
    }
    const combinedSearchToken = options.caseSensitive
      ? token
      : normalizeLowercaseStringOrEmpty(token);
    const combinedCommandIndex =
      options.allowCombinedC && token.startsWith("-") && !token.startsWith("--")
        ? combinedSearchToken.indexOf("c", 1)
        : -1;
    if (combinedCommandIndex > 0) {
      const valueTokenIndex = resolveCombinedPosixCommandOperandIndex(token, i);
      if (valueTokenIndex === null) {
        continue;
      }
      const command = argv[valueTokenIndex]?.trim();
      return {
        command: command ? command : null,
        valueTokenIndex: valueTokenIndex < argv.length ? valueTokenIndex : null,
      };
    }
    if (options.stopAtFirstOperand) {
      if (options.optionConsumesNextArg?.(token) === true) {
        i += 1;
        continue;
      }
      const isOption =
        token.startsWith("-") ||
        (options.allowPlusOptions === true && token.startsWith("+")) ||
        options.isOptionToken?.(token) === true;
      if (!isOption || token === "-" || (options.allowPlusOptions === true && token === "+")) {
        break;
      }
    }
  }
  return { command: null, valueTokenIndex: null };
}
