import { describe, expect, it } from "vitest";
import {
  hasPosixShellStartupOptionBeforeCommandOperand,
  resolvePosixInlineCommandMatch,
} from "./posix-shell-options.js";

describe("hasPosixShellStartupOptionBeforeCommandOperand", () => {
  it.each([
    ["bash", "-lc", "echo ok"],
    ["bash", "-cl", "echo ok"],
    ["bash", "-ci", "echo ok"],
    ["bash", "-olc", "pipefail", "echo ok"],
    ["bash", "-ocl", "pipefail", "echo ok"],
    ["bash", "-Ocl", "extglob", "echo ok"],
    ["bash", "-co", "pipefail", "-i", "echo ok"],
    ["bash", "-cO", "extglob", "-l", "echo ok"],
    ["bash", "-c", "-l", "echo ok"],
    ["bash", "-c", "--login", "echo ok"],
    ["bash", "-c", "-i", "echo ok"],
    ["bash", "-c", "-O", "extglob", "-l", "echo ok"],
    ["bash", "-c", "-o", "pipefail", "-i", "echo ok"],
    ["bash", "--rcfile", "/tmp/rc", "-c", "echo ok"],
    ["zsh", "-f", "-c", "-l"],
    ["zsh", "-c", "echo ok"],
    ["zsh", "-f", "+f", "-c", "echo ok"],
    ["zsh", "-f", "-o", "norcs", "+f", "-c", "echo ok"],
    ["zsh", "--no-rcs", "-o=rcs", "-c", "echo ok"],
  ])("detects startup context for %j", (...argv) => {
    expect(hasPosixShellStartupOptionBeforeCommandOperand(argv)).toBe(true);
  });

  it.each([
    ["bash", "-c", "echo ok"],
    ["bash", "-C", "./script.sh"],
    ["bash", "-oC", "pipefail", "./script.sh"],
    ["bash", "-OC", "extglob", "./script.sh"],
    ["bash", "-c", "--", "-l", "echo ok"],
    ["bash", "-c", "--", "--login", "echo ok"],
    ["bash", "-c", "--", "-i", "echo ok"],
    ["bash", "-c", "--", "-O", "extglob", "-l", "echo ok"],
    ["bash", "-c", "--", "-o", "pipefail", "-i", "echo ok"],
    ["bash", "-c", "-O", "extglob", "echo ok"],
    ["bash", "-c", "-o", "pipefail", "echo ok"],
    ["zsh", "-f", "-c", "echo ok"],
    ["zsh", "-fc", "echo ok"],
    ["zsh", "-cf", "echo ok"],
    ["zsh", "--no-rcs", "-c", "echo ok"],
    ["zsh", "-f", "-o", "norcs", "-c", "echo ok"],
    ["zsh", "+o", "rcs", "-c", "echo ok"],
  ])("allows non-startup context for %j", (...argv) => {
    expect(hasPosixShellStartupOptionBeforeCommandOperand(argv)).toBe(false);
  });

  it.each([
    {
      argv: ["bash", "-lc", "echo ok"],
      expected: { command: "echo ok", valueTokenIndex: 2 },
    },
    {
      argv: ["bash", "-co", "pipefail", "echo ok"],
      expected: { command: "echo ok", valueTokenIndex: 3 },
    },
    {
      argv: ["bash", "-c", "-i", "echo ok"],
      expected: { command: "echo ok", valueTokenIndex: 3 },
    },
    {
      argv: ["bash", "-c", "--", "-i", "echo ok"],
      expected: { command: "-i", valueTokenIndex: 3 },
    },
    {
      argv: ["bash", "--command=echo ok"],
      expected: { command: "echo ok", valueTokenIndex: 1 },
    },
    {
      argv: ["bash", "./script.sh", "-c", "echo ok"],
      expected: { command: null, valueTokenIndex: null },
    },
  ])("resolves POSIX inline command operands for %j", ({ argv, expected }) => {
    expect(resolvePosixInlineCommandMatch(argv)).toEqual(expected);
  });
});
