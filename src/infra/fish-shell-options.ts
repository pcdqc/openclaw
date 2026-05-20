const FISH_SHORT_OPTIONS_WITH_VALUE = new Set(["c", "C", "p", "d", "f", "D", "o"]);
const FISH_LONG_INLINE_COMMAND_OPTIONS = new Set(["--command"]);
const FISH_LONG_STARTUP_COMMAND_OPTIONS = new Set(["--init-command"]);
const FISH_LONG_NO_CONFIG_OPTIONS = new Set(["--no-config"]);
const FISH_LONG_OPTIONS_WITH_VALUE = new Set([
  "--debug",
  "--debug-output",
  "--debug-stack-frames",
  "--features",
  "--profile",
  "--profile-startup",
]);

function splitLongOptionName(token: string): string {
  return token.split("=", 1)[0] ?? token;
}

function readFishShortCommandOption(token: string): {
  kind: "inline" | "startup" | "other";
  noConfig: boolean;
} {
  if (!token.startsWith("-") || token.startsWith("--") || token === "-") {
    return { kind: "other", noConfig: false };
  }

  let noConfig = false;
  for (const flag of token.slice(1)) {
    if (flag === "N") {
      noConfig = true;
      continue;
    }
    if (flag === "c") {
      return { kind: "inline", noConfig };
    }
    if (flag === "C") {
      return { kind: "startup", noConfig };
    }
    if (FISH_SHORT_OPTIONS_WITH_VALUE.has(flag)) {
      return { kind: "other", noConfig };
    }
  }

  return { kind: "other", noConfig };
}

function fishShortOptionConsumesNextArg(token: string): boolean {
  if (!token.startsWith("-") || token.startsWith("--") || token === "-") {
    return false;
  }

  const flags = token.slice(1);
  for (let index = 0; index < flags.length; index += 1) {
    const flag = flags[index] ?? "";
    if (flag === "c" || flag === "C") {
      return false;
    }
    if (!FISH_SHORT_OPTIONS_WITH_VALUE.has(flag)) {
      continue;
    }
    return index === flags.length - 1;
  }

  return false;
}

export function hasFishStartupCommandOptionBeforeCommandOperand(argv: readonly string[]): boolean {
  let noConfig = false;
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index]?.trim() ?? "";
    if (!token) {
      continue;
    }
    if (token === "--") {
      return !noConfig;
    }
    if (!token.startsWith("-")) {
      return !noConfig;
    }
    if (token.startsWith("--")) {
      const optionName = splitLongOptionName(token);
      if (FISH_LONG_STARTUP_COMMAND_OPTIONS.has(optionName)) {
        return true;
      }
      if (FISH_LONG_NO_CONFIG_OPTIONS.has(optionName)) {
        noConfig = true;
        continue;
      }
      if (FISH_LONG_INLINE_COMMAND_OPTIONS.has(optionName)) {
        return !noConfig;
      }
      if (FISH_LONG_OPTIONS_WITH_VALUE.has(optionName) && !token.includes("=")) {
        index += 1;
      }
      continue;
    }

    const shortCommandOption = readFishShortCommandOption(token);
    if (shortCommandOption.noConfig) {
      noConfig = true;
    }
    if (shortCommandOption.kind === "startup") {
      return true;
    }
    if (shortCommandOption.kind === "inline") {
      return !noConfig;
    }
    if (fishShortOptionConsumesNextArg(token)) {
      index += 1;
    }
  }

  return !noConfig;
}
