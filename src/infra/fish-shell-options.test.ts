import { describe, expect, it } from "vitest";
import { hasFishStartupCommandOptionBeforeCommandOperand } from "./fish-shell-options.js";

describe("hasFishStartupCommandOptionBeforeCommandOperand", () => {
  it.each([
    ["fish", "-c", "echo ok"],
    ["fish", "-l", "-c", "echo ok"],
    ["fish", "-i", "-c", "echo ok"],
    ["fish", "--login", "--command", "echo ok"],
    ["fish", "--interactive", "--command=echo ok"],
    ["fish", "-C", "touch /tmp/pwn", "-c", "echo ok"],
    ["fish", "-NCtouch /tmp/pwn", "-c", "echo ok"],
    ["fish", "--init-command", "touch /tmp/pwn", "--command", "echo ok"],
  ])("detects startup context for %j", (...argv) => {
    expect(hasFishStartupCommandOptionBeforeCommandOperand(argv)).toBe(true);
  });

  it.each([
    ["fish", "-N", "-c", "echo ok"],
    ["fish", "-Nc", "echo ok"],
    ["fish", "--no-config", "--command", "echo ok"],
    ["fish", "--no-config", "--command=echo ok"],
    ["fish", "-N", "scripts/run.fish"],
  ])("allows no-config contexts for %j", (...argv) => {
    expect(hasFishStartupCommandOptionBeforeCommandOperand(argv)).toBe(false);
  });
});
