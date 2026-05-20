import { describe, expect, it } from "vitest";
import { isPowerShellOptionToken, powerShellOptionConsumesNextArg } from "./powershell-options.js";
import {
  POSIX_INLINE_COMMAND_FLAGS,
  POWERSHELL_INLINE_COMMAND_FLAGS,
  resolveInlineCommandMatch,
} from "./shell-inline-command.js";

describe("resolveInlineCommandMatch", () => {
  it.each([
    {
      name: "extracts the next token for bash -lc",
      argv: ["bash", "-lc", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      expected: { command: "echo hi", valueTokenIndex: 2 },
    },
    {
      name: "extracts the next token for PowerShell -Command",
      argv: ["pwsh", "-Command", "Get-ChildItem"],
      flags: POWERSHELL_INLINE_COMMAND_FLAGS,
      expected: { command: "Get-ChildItem", valueTokenIndex: 2 },
    },
    {
      name: "skips PowerShell slash switches before command payloads",
      argv: ["pwsh", "/NoProfile", "-Command", "Get-ChildItem"],
      flags: POWERSHELL_INLINE_COMMAND_FLAGS,
      opts: {
        isOptionToken: isPowerShellOptionToken,
        optionConsumesNextArg: powerShellOptionConsumesNextArg,
        stopAtFirstOperand: true,
      },
      expected: { command: "Get-ChildItem", valueTokenIndex: 3 },
    },
    {
      name: "extracts the next token for PowerShell -en",
      argv: ["pwsh", "-en", "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABvAGsA"],
      flags: POWERSHELL_INLINE_COMMAND_FLAGS,
      expected: {
        command: "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABvAGsA",
        valueTokenIndex: 2,
      },
    },
    {
      name: "extracts long inline option values",
      argv: ["fish", "--command=echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { caseSensitive: true },
      expected: { command: "echo hi", valueTokenIndex: 1 },
    },
    {
      name: "extracts the next token for PowerShell -File",
      argv: ["pwsh", "-File", "script.ps1"],
      flags: POWERSHELL_INLINE_COMMAND_FLAGS,
      expected: { command: "script.ps1", valueTokenIndex: 2 },
    },
    {
      name: "extracts the next token for PowerShell -f",
      argv: ["powershell", "-f", "script.ps1"],
      flags: POWERSHELL_INLINE_COMMAND_FLAGS,
      expected: { command: "script.ps1", valueTokenIndex: 2 },
    },
    {
      name: "treats clustered flags after POSIX -c as shell options",
      argv: ["sh", "-ce", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: true },
      expected: { command: "echo hi", valueTokenIndex: 2 },
    },
    {
      name: "does not treat text after POSIX -c as an inline command",
      argv: ["sh", "-cecho hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: true },
      expected: { command: null, valueTokenIndex: null },
    },
    {
      name: "treats startup flags after combined POSIX -c as options",
      argv: ["bash", "-cl", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: true, caseSensitive: true },
      expected: { command: "echo hi", valueTokenIndex: 2 },
    },
    {
      name: "treats interactive flags after combined POSIX -c as options",
      argv: ["bash", "-ci", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: true, caseSensitive: true },
      expected: { command: "echo hi", valueTokenIndex: 2 },
    },
    {
      name: "skips value-taking flags in POSIX -c clusters",
      argv: ["bash", "-co", "pipefail", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: true, caseSensitive: true },
      expected: { command: "echo hi", valueTokenIndex: 3 },
    },
    {
      name: "skips value-taking flags before POSIX -c in the same cluster",
      argv: ["bash", "-oc", "pipefail", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: true, caseSensitive: true },
      expected: { command: "echo hi", valueTokenIndex: 3 },
    },
    {
      name: "stops before POSIX script operands",
      argv: ["bash", "./script.sh", "-c", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: true, caseSensitive: true, stopAtFirstOperand: true },
      expected: { command: null, valueTokenIndex: null },
    },
    {
      name: "skips POSIX option values before stopping at operands",
      argv: ["bash", "-o", "pipefail", "-c", "echo hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: {
        allowCombinedC: true,
        caseSensitive: true,
        optionConsumesNextArg: (token: string) => token === "-o",
        stopAtFirstOperand: true,
      },
      expected: { command: "echo hi", valueTokenIndex: 4 },
    },
    {
      name: "rejects combined -c forms when disabled",
      argv: ["sh", "-cecho hi"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      opts: { allowCombinedC: false },
      expected: { command: null, valueTokenIndex: null },
    },
    {
      name: "returns a value index for blank command tokens",
      argv: ["bash", "-lc", "   "],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      expected: { command: null, valueTokenIndex: 2 },
    },
    {
      name: "returns null value index when the flag has no following token",
      argv: ["bash", "-lc"],
      flags: POSIX_INLINE_COMMAND_FLAGS,
      expected: { command: null, valueTokenIndex: null },
    },
  ])("$name", ({ argv, flags, opts, expected }) => {
    expect(resolveInlineCommandMatch(argv, flags, opts)).toEqual(expected);
  });

  it("stops parsing after --", () => {
    expect(
      resolveInlineCommandMatch(["bash", "--", "-lc", "echo hi"], POSIX_INLINE_COMMAND_FLAGS),
    ).toEqual({
      command: null,
      valueTokenIndex: null,
    });
  });
});
