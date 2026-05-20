import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveAllowAlwaysPatternEntries } from "./exec-approvals-allowlist.js";
import {
  makeMockCommandResolution,
  makeMockExecutableResolution,
  makePathEnv,
  makeTempDir,
} from "./exec-approvals-test-helpers.js";
import {
  analyzeArgvCommand,
  evaluateExecAllowlist,
  evaluateShellAllowlist,
  hasDurableExecApproval,
  requiresExecApproval,
  resolveAllowAlwaysPatterns,
  resolveSafeBins,
} from "./exec-approvals.js";

function durableCommandPattern(commandText: string, cwd: string | null = null): string {
  return `=command:${crypto
    .createHash("sha256")
    .update(JSON.stringify(["v1", commandText.trim(), cwd, null]))
    .digest("hex")
    .slice(0, 16)}`;
}
import { matchAllowlist } from "./exec-command-resolution.js";

describe("resolveAllowAlwaysPatterns", () => {
  function makeExecutable(dir: string, name: string): string {
    const fileName = process.platform === "win32" ? `${name}.exe` : name;
    const exe = path.join(dir, fileName);
    fs.writeFileSync(exe, "");
    fs.chmodSync(exe, 0o755);
    return exe;
  }

  function resolvePersistedPatterns(params: {
    command: string;
    dir: string;
    env: Record<string, string | undefined>;
    safeBins: ReturnType<typeof resolveSafeBins>;
    strictInlineEval?: boolean;
  }) {
    const analysis = evaluateShellAllowlist({
      command: params.command,
      allowlist: [],
      safeBins: params.safeBins,
      cwd: params.dir,
      env: params.env,
      platform: process.platform,
    });
    return {
      analysis,
      persisted: resolveAllowAlwaysPatterns({
        segments: analysis.segments,
        cwd: params.dir,
        env: params.env,
        platform: process.platform,
        strictInlineEval: params.strictInlineEval,
      }),
    };
  }

  function expectAllowAlwaysBypassBlocked(params: {
    dir: string;
    firstCommand: string;
    secondCommand: string;
    env: Record<string, string | undefined>;
    persistedPattern: string;
  }) {
    const safeBins = resolveSafeBins(undefined);
    const { persisted } = resolvePersistedPatterns({
      command: params.firstCommand,
      dir: params.dir,
      env: params.env,
      safeBins,
    });
    expect(persisted).toEqual([params.persistedPattern]);

    const second = evaluateShellAllowlist({
      command: params.secondCommand,
      allowlist: [{ pattern: params.persistedPattern }],
      safeBins,
      cwd: params.dir,
      env: params.env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
    expect(
      requiresExecApproval({
        ask: "on-miss",
        security: "allowlist",
        analysisOk: second.analysisOk,
        allowlistSatisfied: second.allowlistSatisfied,
      }),
    ).toBe(true);
  }

  function createShellScriptFixture() {
    const dir = makeTempDir();
    const scriptsDir = path.join(dir, "scripts");
    fs.mkdirSync(scriptsDir, { recursive: true });
    const script = path.join(scriptsDir, "save_crystal.sh");
    fs.writeFileSync(script, "echo ok\n");
    const env = { PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}` };
    const safeBins = resolveSafeBins(undefined);
    return { dir, scriptsDir, script, env, safeBins };
  }

  function expectPersistedShellScriptMatch(params: {
    command: string;
    script: string;
    dir: string;
    env: Record<string, string | undefined>;
    safeBins: ReturnType<typeof resolveSafeBins>;
  }) {
    const { persisted } = resolvePersistedPatterns({
      command: params.command,
      dir: params.dir,
      env: params.env,
      safeBins: params.safeBins,
    });
    expect(persisted).toEqual([params.script]);

    const second = evaluateShellAllowlist({
      command: params.command,
      allowlist: [{ pattern: params.script }],
      safeBins: params.safeBins,
      cwd: params.dir,
      env: params.env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(true);
  }

  function expectShellScriptFallbackRejected(command: string) {
    const { dir, scriptsDir, script, env, safeBins } = createShellScriptFixture();
    const rcFile = path.join(scriptsDir, "evilrc");
    fs.writeFileSync(rcFile, "echo blocked\n");

    const { persisted } = resolvePersistedPatterns({
      command,
      dir,
      env,
      safeBins,
    });
    expect(persisted).toEqual([]);

    const second = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: script }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
  }

  function expectPositionalArgvCarrierResult(params: {
    command: string;
    expectPersisted: boolean;
  }) {
    const dir = makeTempDir();
    const touch = makeExecutable(dir, "touch");
    const env = { PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}` };
    const safeBins = resolveSafeBins(undefined);
    const marker = path.join(dir, "marker");
    const command = params.command.replaceAll("{marker}", marker);

    const { persisted } = resolvePersistedPatterns({
      command,
      dir,
      env,
      safeBins,
    });
    if (params.expectPersisted) {
      expect(persisted).toEqual([touch]);
    } else {
      expect(persisted).toEqual([]);
    }

    const second = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: touch }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(params.expectPersisted);
  }

  it("returns direct executable paths for non-shell segments", () => {
    const exe = path.join("/tmp", "openclaw-tool");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: exe,
          argv: [exe],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: exe,
              resolvedPath: exe,
              executableName: "openclaw-tool",
            }),
          }),
        },
      ],
    });
    expect(patterns).toEqual([exe]);
  });

  it("does not persist interpreter-like executables for allow-always", () => {
    const awk = path.join("/tmp", "awk");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: `${awk} '{print $1}' data.csv`,
          argv: [awk, "{print $1}", "data.csv"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: awk,
              resolvedPath: awk,
              executableName: "awk",
            }),
          }),
        },
      ],
    });
    expect(patterns).toEqual([]);
  });

  it("persists benign awk interpreters when strict inline-eval is enabled", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const awk = makeExecutable(dir, "awk");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const { persisted } = resolvePersistedPatterns({
      command: "awk -F, -f script.awk data.csv",
      dir,
      env,
      safeBins,
      strictInlineEval: true,
    });
    expect(persisted).toEqual([awk]);

    const second = evaluateShellAllowlist({
      command: "awk -F, -f script.awk data.csv",
      allowlist: persisted.map((pattern) => ({ pattern })),
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(true);
  });

  it("keeps Windows strict inline-eval interpreter approvals argv-bound", () => {
    const awk = "C:\\temp\\awk.exe";
    const resolution = makeMockCommandResolution({
      execution: makeMockExecutableResolution({
        rawExecutable: awk,
        resolvedPath: awk,
        executableName: "awk",
      }),
    });
    const entries = resolveAllowAlwaysPatternEntries({
      segments: [
        {
          raw: `${awk} -F , -f script.awk data.csv`,
          argv: [awk, "-F", ",", "-f", "script.awk", "data.csv"],
          resolution,
        },
      ],
      platform: "win32",
      strictInlineEval: true,
    });

    expect(entries).toEqual([
      expect.objectContaining({
        pattern: awk,
        argPattern: expect.any(String),
      }),
    ]);
    expect(
      matchAllowlist(
        entries,
        resolution.execution ?? null,
        [awk, "-F", ",", "-f", "script.awk", "data.csv"],
        "win32",
      ),
    ).toEqual(expect.objectContaining({ pattern: awk, argPattern: expect.any(String) }));
    expect(
      matchAllowlist(
        entries,
        resolution.execution ?? null,
        [awk, "-f", "other.awk", "secrets.csv"],
        "win32",
      ),
    ).toBeNull();
  });

  it("keeps inline awk programs out of allow-always persistence in strict inline-eval mode", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    makeExecutable(dir, "awk");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const { persisted } = resolvePersistedPatterns({
      command: `awk 'BEGIN{system("id > ${path.join(dir, "marker")}")}'`,
      dir,
      env,
      safeBins,
      strictInlineEval: true,
    });
    expect(persisted).toEqual([]);
  });

  it("unwraps shell wrappers and persists the inner executable instead", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const whoami = makeExecutable(dir, "whoami");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: "/bin/zsh -f -c 'whoami'",
          argv: ["/bin/zsh", "-f", "-c", "whoami"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: "/bin/zsh",
              resolvedPath: "/bin/zsh",
              executableName: "zsh",
            }),
          }),
        },
      ],
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });
    expect(patterns).toEqual([whoami]);
    expect(patterns).not.toContain("/bin/zsh");
  });

  it("extracts all inner binaries from shell chains and deduplicates", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const whoami = makeExecutable(dir, "whoami");
    const ls = makeExecutable(dir, "ls");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: "/bin/zsh -f -c 'whoami && ls && whoami'",
          argv: ["/bin/zsh", "-f", "-c", "whoami && ls && whoami"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: "/bin/zsh",
              resolvedPath: "/bin/zsh",
              executableName: "zsh",
            }),
          }),
        },
      ],
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });
    expect(new Set(patterns)).toEqual(new Set([whoami, ls]));
  });

  it("persists shell script paths for wrapper invocations without inline commands", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, scriptsDir, script, env, safeBins } = createShellScriptFixture();
    expectPersistedShellScriptMatch({
      command: "bash scripts/save_crystal.sh",
      script,
      dir,
      env,
      safeBins,
    });

    const other = path.join(scriptsDir, "other.sh");
    fs.writeFileSync(other, "echo other\n");
    const third = evaluateShellAllowlist({
      command: "bash scripts/other.sh",
      allowlist: [{ pattern: script }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(third.allowlistSatisfied).toBe(false);
  });

  it("matches persisted shell script paths through dispatch wrappers", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, script, env, safeBins } = createShellScriptFixture();
    expectPersistedShellScriptMatch({
      command: "/usr/bin/nice bash scripts/save_crystal.sh",
      script,
      dir,
      env,
      safeBins,
    });
  });

  it("persists POSIX shell script paths after uppercase -C", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, script, env, safeBins } = createShellScriptFixture();
    expectPersistedShellScriptMatch({
      command: "bash -C scripts/save_crystal.sh",
      script,
      dir,
      env,
      safeBins,
    });
  });

  it("rejects POSIX shell startup flags before shell script paths", () => {
    if (process.platform === "win32") {
      return;
    }
    for (const command of [
      "bash --login -C scripts/save_crystal.sh",
      "bash -l -C scripts/save_crystal.sh",
      "bash -i -C scripts/save_crystal.sh",
      "bash -lC scripts/save_crystal.sh",
      "bash -O extglob -l -C scripts/save_crystal.sh",
    ]) {
      expectShellScriptFallbackRejected(command);
    }
  });

  it("rejects POSIX shell startup flags before positional argv carriers", () => {
    if (process.platform === "win32") {
      return;
    }
    for (const command of [
      `bash --rcfile scripts/evilrc -ic '$0 "$1"' touch {marker}`,
      `bash --rcfile=scripts/evilrc -ic '$0 "$1"' touch {marker}`,
      `bash --login -c '$0 "$1"' touch {marker}`,
      `bash -ic '$0 "$1"' touch {marker}`,
      `bash -ci '$0 "$1"' touch {marker}`,
      `bash -l -c '$0 "$1"' touch {marker}`,
      `bash -lc '$0 "$1"' touch {marker}`,
      `bash -cl '$0 "$1"' touch {marker}`,
      `bash -O extglob -l -c '$0 "$1"' touch {marker}`,
      `zsh -c '$0 "$1"' touch {marker}`,
      `zsh -f +f -c '$0 "$1"' touch {marker}`,
      `zsh -f -o norcs +f -c '$0 "$1"' touch {marker}`,
      `zsh --no-rcs -o=rcs -c '$0 "$1"' touch {marker}`,
    ]) {
      expectPositionalArgvCarrierResult({
        command,
        expectPersisted: false,
      });
    }
  });

  it("rejects POSIX shell startup flags before inline command unwrapping", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const whoami = makeExecutable(dir, "whoami");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);
    fs.writeFileSync(path.join(dir, "evilrc"), "echo blocked\n");

    for (const command of [
      `bash --rcfile ./evilrc -ic "whoami && whoami"`,
      `bash --rcfile=./evilrc -ic "whoami && whoami"`,
      `bash --login -c "whoami && whoami"`,
      `bash -lc "whoami && whoami"`,
      `bash -cl "whoami && whoami"`,
      `fish -c "whoami && whoami"`,
      `fish -l -c "whoami && whoami"`,
      `fish -i -c "whoami && whoami"`,
      `fish --login --command "whoami && whoami"`,
      `fish --interactive --command "whoami && whoami"`,
      `zsh -c "whoami && whoami"`,
      `zsh -f +f -c "whoami && whoami"`,
      `zsh -f -o norcs +f -c "whoami && whoami"`,
      `zsh --no-rcs -o=rcs -c "whoami && whoami"`,
    ]) {
      const { persisted } = resolvePersistedPatterns({
        command,
        dir,
        env,
        safeBins,
      });
      expect(persisted).toEqual([]);

      const second = evaluateShellAllowlist({
        command,
        allowlist: [{ pattern: whoami }],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });
      expect(second.allowlistSatisfied).toBe(false);
    }
  });

  it("rejects fish startup commands as persisted or allowlisted script paths", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, scriptsDir, script, env, safeBins } = createShellScriptFixture();
    makeExecutable(dir, "fish");
    const initCommand = path.join(scriptsDir, "init.fish");
    fs.writeFileSync(initCommand, "echo init\n");

    for (const command of [
      "fish -C scripts/init.fish scripts/save_crystal.sh",
      "fish -Cscripts/init.fish scripts/save_crystal.sh",
      "fish -NCscripts/init.fish scripts/save_crystal.sh",
      "fish --init-command scripts/init.fish scripts/save_crystal.sh",
      "fish --init-command=scripts/init.fish scripts/save_crystal.sh",
    ]) {
      const { persisted } = resolvePersistedPatterns({
        command,
        dir,
        env,
        safeBins,
      });
      expect(persisted).toEqual([]);
      for (const pattern of [initCommand, script]) {
        const second = evaluateShellAllowlist({
          command,
          allowlist: [{ pattern }],
          safeBins,
          cwd: dir,
          env,
          platform: process.platform,
        });
        expect(second.allowlistSatisfied).toBe(false);
      }
    }
  });

  it("rejects shell rc and init-file options as persisted or allowlisted script paths", () => {
    if (process.platform === "win32") {
      return;
    }
    for (const command of [
      "bash --rcfile scripts/evilrc scripts/save_crystal.sh",
      "bash --init-file scripts/evilrc scripts/save_crystal.sh",
      "bash --startup-file scripts/evilrc scripts/save_crystal.sh",
    ]) {
      expectShellScriptFallbackRejected(command);
    }
  });

  it("rejects shell rc and init-file equals options as persisted or allowlisted script paths", () => {
    if (process.platform === "win32") {
      return;
    }
    for (const command of [
      "bash --rcfile=scripts/evilrc scripts/save_crystal.sh",
      "bash --init-file=scripts/evilrc scripts/save_crystal.sh",
      "bash --startup-file=scripts/evilrc scripts/save_crystal.sh",
    ]) {
      expectShellScriptFallbackRejected(command);
    }
  });

  it("persists shell-wrapper positional argv carriers without startup context", () => {
    if (process.platform === "win32") {
      return;
    }
    expectPositionalArgvCarrierResult({
      command: `sh -c '$0 "$1"' touch {marker}`,
      expectPersisted: true,
    });
    expectPositionalArgvCarrierResult({
      command: `zsh -f -c '$0 "$1"' touch {marker}`,
      expectPersisted: true,
    });
  });

  it("does not treat later -c as a carrier after a shell script operand", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const touch = makeExecutable(dir, "touch");
    fs.writeFileSync(path.join(dir, "evil.sh"), "echo evil\n");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);
    const command = `bash -C ./evil.sh -c '$0 "$1"' touch marker`;

    const analysis = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: touch }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(analysis.allowlistSatisfied).toBe(false);
    expect(
      resolveAllowAlwaysPatterns({
        segments: analysis.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([]);
  });

  it("rejects exec positional argv carriers", () => {
    if (process.platform === "win32") {
      return;
    }
    expectPositionalArgvCarrierResult({
      command: `sh -c 'exec -- "$0" "$1"' touch {marker}`,
      expectPersisted: true,
    });
  });

  it("rejects positional argv carriers when $0 is single-quoted", () => {
    if (process.platform === "win32") {
      return;
    }
    expectPositionalArgvCarrierResult({
      command: `sh -c "'$0' "$1"" touch {marker}`,
      expectPersisted: false,
    });
  });

  it("rejects positional argv carriers when exec is separated from $0 by a newline", () => {
    if (process.platform === "win32") {
      return;
    }
    expectPositionalArgvCarrierResult({
      command: `sh -c "exec
$0 \\"$1\\"" touch {marker}`,
      expectPersisted: false,
    });
  });

  it("rejects positional argv carriers when inline command contains extra shell operations", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const touch = makeExecutable(dir, "touch");
    const env = { PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}` };
    const safeBins = resolveSafeBins(undefined);
    const marker = path.join(dir, "marker");

    const { persisted } = resolvePersistedPatterns({
      command: `sh -c 'echo blocked; $0 "$1"' touch ${marker}`,
      dir,
      env,
      safeBins,
    });
    expect(persisted).not.toContain(touch);

    const second = evaluateShellAllowlist({
      command: `sh -c 'echo blocked; $0 "$1"' touch ${marker}`,
      allowlist: [{ pattern: touch }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
  });

  it("does not treat inline shell commands as persisted script paths", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, script, env } = createShellScriptFixture();
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "bash scripts/save_crystal.sh",
      secondCommand: "bash -c 'scripts/save_crystal.sh'",
      env,
      persistedPattern: script,
    });
  });

  it("does not treat stdin shell mode as a persisted script path", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, script, env } = createShellScriptFixture();
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "bash scripts/save_crystal.sh",
      secondCommand: "bash -s scripts/save_crystal.sh",
      env,
      persistedPattern: script,
    });
  });

  it("does not persist broad shell binaries when no inner command can be derived", () => {
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: "/bin/zsh -s",
          argv: ["/bin/zsh", "-s"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: "/bin/zsh",
              resolvedPath: "/bin/zsh",
              executableName: "zsh",
            }),
          }),
        },
      ],
      platform: process.platform,
    });
    expect(patterns).toEqual([]);
  });

  it("detects shell wrappers even when unresolved executableName is a full path", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const whoami = makeExecutable(dir, "whoami");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: "/usr/local/bin/zsh -f -c whoami",
          argv: ["/usr/local/bin/zsh", "-f", "-c", "whoami"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: "/usr/local/bin/zsh",
              resolvedPath: undefined,
              executableName: "/usr/local/bin/zsh",
            }),
          }),
        },
      ],
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });
    expect(patterns).toEqual([whoami]);
  });

  it("unwraps known dispatch wrappers before shell wrappers", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const whoami = makeExecutable(dir, "whoami");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: "/usr/bin/nice /bin/zsh -f -c whoami",
          argv: ["/usr/bin/nice", "/bin/zsh", "-f", "-c", "whoami"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: "/usr/bin/nice",
              resolvedPath: "/usr/bin/nice",
              executableName: "nice",
            }),
          }),
        },
      ],
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });
    expect(patterns).toEqual([whoami]);
    expect(patterns).not.toContain("/usr/bin/nice");
  });

  it("unwraps time wrappers and persists the inner executable instead", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const whoami = makeExecutable(dir, "whoami");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: "/usr/bin/time -p /bin/zsh -f -c whoami",
          argv: ["/usr/bin/time", "-p", "/bin/zsh", "-f", "-c", "whoami"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: "/usr/bin/time",
              resolvedPath: "/usr/bin/time",
              executableName: "time",
            }),
          }),
        },
      ],
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });
    expect(patterns).toEqual([whoami]);
    expect(patterns).not.toContain("/usr/bin/time");
  });

  it("unwraps busybox/toybox shell applets and persists inner executables", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const busybox = makeExecutable(dir, "busybox");
    makeExecutable(dir, "toybox");
    const whoami = makeExecutable(dir, "whoami");
    const env = { PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}` };
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: `${busybox} sh -c whoami`,
          argv: [busybox, "sh", "-c", "whoami"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: busybox,
              resolvedPath: busybox,
              executableName: "busybox",
            }),
          }),
        },
      ],
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(patterns).toEqual([whoami]);
    expect(patterns).not.toContain(busybox);
  });

  it("fails closed for unsupported busybox/toybox applets", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const busybox = makeExecutable(dir, "busybox");
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: `${busybox} sed -n 1p`,
          argv: [busybox, "sed", "-n", "1p"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: busybox,
              resolvedPath: busybox,
              executableName: "busybox",
            }),
          }),
        },
      ],
      cwd: dir,
      env: makePathEnv(dir),
      platform: process.platform,
    });
    expect(patterns).toEqual([]);
  });

  it("fails closed for unresolved dispatch wrappers", () => {
    const patterns = resolveAllowAlwaysPatterns({
      segments: [
        {
          raw: "sudo /bin/zsh -lc whoami",
          argv: ["sudo", "/bin/zsh", "-lc", "whoami"],
          resolution: makeMockCommandResolution({
            execution: makeMockExecutableResolution({
              rawExecutable: "sudo",
              resolvedPath: "/usr/bin/sudo",
              executableName: "sudo",
            }),
          }),
        },
      ],
      platform: process.platform,
    });
    expect(patterns).toEqual([]);
  });

  it("prevents allow-always bypass for busybox shell applets", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const busybox = makeExecutable(dir, "busybox");
    const echo = makeExecutable(dir, "echo");
    makeExecutable(dir, "id");
    const env = { PATH: `${dir}${path.delimiter}${process.env.PATH ?? ""}` };
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: `${busybox} sh -c 'echo warmup-ok'`,
      secondCommand: `${busybox} sh -c 'id > marker'`,
      env,
      persistedPattern: echo,
    });
  });

  it("prevents allow-always bypass for caffeinate wrapper chains", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const echo = makeExecutable(dir, "echo");
    makeExecutable(dir, "id");
    const env = makePathEnv(dir);
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "/usr/bin/caffeinate -d -w 42 /bin/zsh -f -c 'echo warmup-ok'",
      secondCommand: "/usr/bin/caffeinate -d -w 42 /bin/zsh -f -c 'id > marker'",
      env,
      persistedPattern: echo,
    });
  });

  it("prevents allow-always bypass for dispatch-wrapper + shell-wrapper chains", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const echo = makeExecutable(dir, "echo");
    makeExecutable(dir, "id");
    const env = makePathEnv(dir);
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "/usr/bin/nice /bin/zsh -f -c 'echo warmup-ok'",
      secondCommand: "/usr/bin/nice /bin/zsh -f -c 'id > marker'",
      env,
      persistedPattern: echo,
    });
  });

  it("prevents allow-always bypass for sandbox-exec wrapper chains", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const echo = makeExecutable(dir, "echo");
    makeExecutable(dir, "id");
    const env = makePathEnv(dir);
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand:
        "/usr/bin/sandbox-exec -p '(deny default) (allow process*)' /bin/zsh -f -c 'echo warmup-ok'",
      secondCommand: "/usr/bin/sandbox-exec -p '(allow default)' /bin/zsh -f -c 'id > marker'",
      env,
      persistedPattern: echo,
    });
  });

  it("prevents allow-always bypass for time wrapper chains", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const echo = makeExecutable(dir, "echo");
    makeExecutable(dir, "id");
    const env = makePathEnv(dir);
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "/usr/bin/time -p /bin/zsh -f -c 'echo warmup-ok'",
      secondCommand: "/usr/bin/time -p /bin/zsh -f -c 'id > marker'",
      env,
      persistedPattern: echo,
    });
  });

  it("prevents allow-always bypass for macOS dispatch-wrapper chains", () => {
    if (process.platform !== "darwin") {
      return;
    }
    const dir = makeTempDir();
    const echo = makeExecutable(dir, "echo");
    makeExecutable(dir, "id");
    const env = makePathEnv(dir);
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "/usr/bin/arch -arm64 /bin/zsh -f -c 'echo warmup-ok'",
      secondCommand: "/usr/bin/arch -arm64 /bin/zsh -f -c 'id > marker-arch'",
      env,
      persistedPattern: echo,
    });
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "/usr/bin/xcrun /bin/zsh -f -c 'echo warmup-ok'",
      secondCommand: "/usr/bin/xcrun /bin/zsh -f -c 'id > marker-xcrun'",
      env,
      persistedPattern: echo,
    });
  });

  it("prevents allow-always bypass for awk interpreters", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    makeExecutable(dir, "awk");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const { persisted } = resolvePersistedPatterns({
      command: "awk '{print $1}' data.csv",
      dir,
      env,
      safeBins,
    });
    expect(persisted).toEqual([]);

    const second = evaluateShellAllowlist({
      command: `awk 'BEGIN{system("id > ${path.join(dir, "marker")}")}'`,
      allowlist: persisted.map((pattern) => ({ pattern })),
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
    expect(
      requiresExecApproval({
        ask: "on-miss",
        security: "allowlist",
        analysisOk: second.analysisOk,
        allowlistSatisfied: second.allowlistSatisfied,
      }),
    ).toBe(true);
  });

  it("prevents allow-always bypass for shell-carried awk interpreters", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    makeExecutable(dir, "awk");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const { persisted } = resolvePersistedPatterns({
      command: `sh -c '$0 "$@"' awk '{print $1}' data.csv`,
      dir,
      env,
      safeBins,
    });
    expect(persisted).toEqual([]);

    const second = evaluateShellAllowlist({
      command: `sh -c '$0 "$@"' awk 'BEGIN{system("id > /tmp/pwned")}'`,
      allowlist: persisted.map((pattern) => ({ pattern })),
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
  });

  it("prevents allow-always bypass for script wrapper chains", () => {
    if (process.platform !== "darwin" && process.platform !== "freebsd") {
      return;
    }
    const dir = makeTempDir();
    const echo = makeExecutable(dir, "echo");
    makeExecutable(dir, "id");
    const env = makePathEnv(dir);
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: "/usr/bin/script -q /dev/null /bin/sh -c 'echo warmup-ok'",
      secondCommand: "/usr/bin/script -q /dev/null /bin/sh -c 'id > marker'",
      env,
      persistedPattern: echo,
    });
  });

  it("does not persist comment-tailed payload paths that never execute", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const benign = makeExecutable(dir, "benign");
    makeExecutable(dir, "payload");
    const env = makePathEnv(dir);
    expectAllowAlwaysBypassBlocked({
      dir,
      firstCommand: `${benign} warmup # && payload`,
      secondCommand: "payload",
      env,
      persistedPattern: benign,
    });
  });

  it("rejects positional carrier when carried executable is a dispatch wrapper", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const envPath = makeExecutable(dir, "env");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const { persisted } = resolvePersistedPatterns({
      command: `sh -c '$0 "$@"' env echo SAFE`,
      dir,
      env,
      safeBins,
    });
    expect(persisted).toEqual([]);

    const envShellCarrier = evaluateShellAllowlist({
      command: `sh -c '$0 "$@"' env BASH_ENV=/tmp/payload.sh bash -lc 'id > /tmp/pwned'`,
      allowlist: [],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(envShellCarrier.exactCommandDurableApprovalAllowed).toBe(false);
    expect(
      resolveAllowAlwaysPatterns({
        segments: envShellCarrier.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([]);

    const second = evaluateShellAllowlist({
      command: `sh -c '$0 "$@"' env BASH_ENV=/tmp/payload.sh bash -lc 'id > /tmp/pwned'`,
      allowlist: [{ pattern: envPath }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
  });

  it("blocks exact durable trust for env-manipulated shell script wrappers", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, script, env, safeBins } = createShellScriptFixture();
    makeExecutable(dir, "bash");

    const { analysis, persisted } = resolvePersistedPatterns({
      command: "env BASH_ENV=/tmp/payload bash scripts/save_crystal.sh",
      dir,
      env,
      safeBins,
    });

    expect(persisted).toEqual([]);
    expect(analysis.exactCommandDurableApprovalAllowed).toBe(false);

    const second = evaluateShellAllowlist({
      command: "env BASH_ENV=/tmp/changed bash scripts/save_crystal.sh",
      allowlist: [{ pattern: script }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
    expect(second.exactCommandDurableApprovalAllowed).toBe(false);
  });

  it("blocks exact durable trust for shell wrappers after earlier env-mutating chains", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);
    for (const command of [
      `. ./env.sh && sh -c "echo ok"`,
      `export FOO=bar && bash -lc "echo ok"`,
      `export BASH_ENV=/tmp/payload && bash -c "echo ok"`,
      `command export BASH_ENV=/tmp/payload; bash -c "echo ok"`,
      `command -p export BASH_ENV=/tmp/payload && bash -c "echo ok"`,
      `command -- export BASH_ENV=/tmp/payload && bash -c "echo ok"`,
      `command eval 'export BASH_ENV=/tmp/payload' && bash -c "echo ok"`,
      `builtin export BASH_ENV=/tmp/payload && bash -c "echo ok"`,
      `builtin eval 'export BASH_ENV=/tmp/payload' && bash -c "echo ok"`,
      `PATH=/tmp && bash -c "echo ok"`,
      `readonly -x BASH_ENV=/tmp/payload && bash -c "echo ok"`,
      `source ./env.sh && bash -c "echo ok"`,
      `eval 'export BASH_ENV=/tmp/payload' && bash -c "echo ok"`,
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
      expect(
        resolveAllowAlwaysPatterns({
          segments: analysis.segments,
          cwd: dir,
          env,
          platform: process.platform,
        }),
        command,
      ).toEqual([]);
    }
  });

  it("blocks exact durable trust for grouped shell syntax after env mutation", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);
    const command = `export BASH_ENV=/tmp/payload; { bash -c "echo ok"; }`;

    const analysis = evaluateShellAllowlist({
      command,
      allowlist: [],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(analysis.exactCommandDurableApprovalAllowed).toBe(false);
    expect(
      resolveAllowAlwaysPatterns({
        segments: analysis.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([]);
  });

  it("blocks exact durable trust for nested shell wrappers after env-mutating chains", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const echoPath = makeExecutable(dir, "echo");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const command of [
      `sh -c 'export FOO=bar && bash -c "echo ok"'`,
      `sh -c 'export BASH_ENV=/tmp/payload && bash -c "echo ok"'`,
      `zsh -fc 'readonly -x BASH_ENV=/tmp/payload && bash -c "echo ok"'`,
      `sh -c 'unset BASH_ENV && bash -c "echo ok"'`,
      `sh -c 'export ENV=/tmp/payload && sh -c "echo ok"'`,
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [{ pattern: echoPath }],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
      expect(
        resolveAllowAlwaysPatterns({
          segments: analysis.segments,
          cwd: dir,
          env,
          platform: process.platform,
        }),
        command,
      ).toEqual([]);
    }
  });

  it("blocks exact durable trust for startup shells nested in inline shell payloads", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const command of [
      `bash -c -l "echo ok"`,
      `bash -c --login "echo ok"`,
      `bash -c -i "echo ok"`,
      `bash -c -O extglob -l "echo ok"`,
      `bash -c -o pipefail -i "echo ok"`,
      `bash -co pipefail -i "echo ok"`,
      `bash -cO extglob -l "echo ok"`,
      `sh -c 'bash -lc "echo ok"'`,
      `sh -c 'bash -c -l "echo ok"'`,
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
      expect(
        resolveAllowAlwaysPatterns({
          segments: analysis.segments,
          cwd: dir,
          env,
          platform: process.platform,
        }),
        command,
      ).toEqual([]);
    }
  });

  it("allows exact durable trust when POSIX inline payload starts with option-like text", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const command of [
      `bash -c -- -l "echo ok"`,
      `bash -c -- --login "echo ok"`,
      `bash -c -- -i "echo ok"`,
      `bash -c -- -O extglob -l "echo ok"`,
      `bash -c -- -o pipefail -i "echo ok"`,
      `sh -c 'bash -c -- -l "echo ok"'`,
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(true);
    }
  });

  it("blocks exact durable trust for assignment-prefixed shell wrappers", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);
    const analysis = evaluateShellAllowlist({
      command: `BASH_ENV=/tmp/payload bash -c "echo ok"`,
      allowlist: [],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(analysis.allowlistSatisfied).toBe(false);
    expect(analysis.exactCommandDurableApprovalAllowed).toBe(false);
    expect(
      resolveAllowAlwaysPatterns({
        segments: analysis.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([]);
  });

  it("blocks exact durable trust for cmd and PowerShell startup shells", () => {
    const unsafeCommands = [
      { command: `cmd.exe /c echo ok`, platform: "win32" },
      { command: `pwsh -Command "Write-Output ok"`, platform: "win32" },
      {
        command: `pwsh -WorkingDirectory -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -wo -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -ExecutionPolicy -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -ex -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -if -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -of -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -settings -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `powershell.exe -ExecutionPolicy Bypass -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -Login -NoProfile -Command "Write-Output ok"`,
        platform: "linux",
      },
      {
        command: `pwsh -en VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABvAGsA`,
        platform: "win32",
      },
      { command: `pwsh -NoProfile -File ./script.ps1`, platform: "win32" },
      { command: `pwsh -NoProfile -Fi ./script.ps1`, platform: "win32" },
      { command: `powershell.exe -nop -f ./script.ps1`, platform: "win32" },
      { command: `powershell.exe -nop /file ./script.ps1`, platform: "win32" },
    ] as const;
    for (const { command, platform } of unsafeCommands) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [],
        safeBins: new Set(),
        cwd: process.cwd(),
        env: process.env,
        platform,
      });

      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
    }

    for (const { command, platform } of [
      {
        command: `pwsh -wo -NoProfile -Command "/bin/echo ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -ex -NoProfile -Command "/bin/echo ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -if -NoProfile -Command "/bin/echo ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -of -NoProfile -Command "/bin/echo ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -settings -NoProfile -Command "/bin/echo ok"`,
        platform: "win32",
      },
    ] as const) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [{ pattern: "/bin/echo" }],
        safeBins: new Set(),
        cwd: process.cwd(),
        env: process.env,
        platform,
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
    }

    const loginPayloadAnalysis = evaluateShellAllowlist({
      command: `pwsh -Login -NoProfile -Command "/bin/echo ok && /bin/echo ok"`,
      allowlist: [{ pattern: "/bin/echo" }],
      safeBins: new Set(),
      cwd: process.cwd(),
      env: process.env,
      platform: "linux",
    });
    expect(loginPayloadAnalysis.allowlistSatisfied).toBe(false);
    expect(loginPayloadAnalysis.exactCommandDurableApprovalAllowed).toBe(false);

    const safeCommands = [
      { command: `cmd.exe /d /c echo ok`, platform: "win32" },
      { command: `pwsh -NoProfile -Command "Write-Output ok"`, platform: "win32" },
      {
        command: `pwsh -WorkingDirectory C:/tmp -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -wo C:/tmp -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -ExecutionPolicy Bypass -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      {
        command: `pwsh -ex Bypass -NoProfile -Command "Write-Output ok"`,
        platform: "win32",
      },
      { command: `pwsh -NoProfile --command="Write-Output ok"`, platform: "win32" },
      { command: `pwsh -NoProfile -Command /bin/echo -File`, platform: "win32" },
      {
        command: `pwsh -NoProfile -en VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABvAGsA`,
        platform: "win32",
      },
    ] as const;
    for (const { command, platform } of safeCommands) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [],
        safeBins: new Set(),
        cwd: process.cwd(),
        env: process.env,
        platform,
      });

      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(true);
    }
  });

  it("blocks implicit PowerShell script file execution as a durable script allowlist", () => {
    const dir = makeTempDir();
    const script = path.join(dir, "script.ps1");
    fs.writeFileSync(script, "Write-Output ok\n");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const { command, assertNoPersistedPatterns } of [
      { command: `pwsh -NoProfile ./script.ps1`, assertNoPersistedPatterns: true },
      {
        command: `pwsh -NoProfile ${script} -Command "/bin/echo ok"`,
        assertNoPersistedPatterns: false,
      },
      { command: `powershell.exe -nop script.ps1`, assertNoPersistedPatterns: true },
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [{ pattern: script, source: "allow-always" }],
        safeBins,
        cwd: dir,
        env,
        platform: "win32",
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
      if (assertNoPersistedPatterns) {
        expect(
          resolveAllowAlwaysPatterns({
            segments: analysis.segments,
            cwd: dir,
            env,
            platform: "win32",
          }),
          command,
        ).toEqual([]);
      }
    }
  });

  it("blocks exact durable trust for carrier-wrapped startup shells", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const command of [
      `command bash -lc "echo ok"`,
      `sudo bash -lc "echo ok"`,
      `command sudo bash -lc "echo ok"`,
      `exec sudo bash -lc "echo ok"`,
      `nice command sudo bash -lc "echo ok"`,
      `exec bash -lc "echo ok"`,
      `exec -l bash -c "echo ok"`,
      `exec -a -bash bash -c "echo ok"`,
      `command sh -c 'bash -lc "echo ok"'`,
      `sudo sh -c 'bash -lc "echo ok"'`,
      `command doas sh -c 'bash -lc "echo ok"'`,
      `exec sh -c 'bash -lc "echo ok"'`,
      `env FOO=bar sudo bash -lc "echo ok"`,
      `sudo -i bash -c "echo ok"`,
      `sudo --login bash -c "echo ok"`,
      `sudo -s bash -c "echo ok"`,
      `sudo --shell bash -c "echo ok"`,
      `sudo -i echo ok`,
      `sudo --login echo ok`,
      `sudo -s echo ok`,
      `sudo --shell echo ok`,
      `sudo -i`,
      `sudo -s`,
      `command sudo -i echo ok`,
      `exec sudo -i echo ok`,
      `nice command sudo -i echo ok`,
      `command doas -s echo ok`,
      `exec doas -s echo ok`,
      `sudo -E bash -c "echo ok"`,
      `sudo --preserve-env=BASH_ENV bash -c "echo ok"`,
      `doas -s bash -c "echo ok"`,
      `doas -s echo ok`,
      `doas -s`,
      `command command command command command bash -lc "echo ok"`,
      `env BASH_ENV=/tmp/payload sudo bash -c "echo ok"`,
      `BASH_ENV=/tmp/payload sudo bash -c "echo ok"`,
      `BASH_ENV=/tmp/payload command bash -c "echo ok"`,
      `sudo BASH_ENV=/tmp/payload bash -c "echo ok"`,
      `sudo env BASH_ENV=/tmp/payload bash -c "echo ok"`,
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
      expect(
        resolveAllowAlwaysPatterns({
          segments: analysis.segments,
          cwd: dir,
          env,
          platform: process.platform,
        }),
        command,
      ).toEqual([]);
    }
  });

  it("does not reuse carrier allowlists for carried sudo startup contexts", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const commandPath = makeExecutable(dir, "command");
    makeExecutable(dir, "nice");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const command of [`command sudo -i id`, `command doas -s id`, `nice command sudo -i id`]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [{ pattern: commandPath, source: "allow-always" }],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
    }
  });

  it("does not allowlist carrier binaries after shell-wrapper carrier depth overflow", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const commandPath = makeExecutable(dir, "command");
    makeExecutable(dir, "bash");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);
    const command = `command command command command command bash -lc "echo ok"`;

    const analysis = evaluateShellAllowlist({
      command,
      allowlist: [{ pattern: commandPath, source: "allow-always" }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(analysis.allowlistSatisfied).toBe(false);
    expect(analysis.exactCommandDurableApprovalAllowed).toBe(false);
    expect(analysis.segmentAllowlistEntries).toEqual([null]);
    expect(
      resolveAllowAlwaysPatterns({
        segments: analysis.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([]);
  });

  it("blocks allowlisted inner commands through policy-blocked shell carriers", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const echoPath = makeExecutable(dir, "echo");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const command of [
      `command sudo sh -c "${echoPath} ok && ${echoPath} again"`,
      `exec sudo sh -c "${echoPath} ok && ${echoPath} again"`,
      `nice command doas sh -c "${echoPath} ok && ${echoPath} again"`,
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [{ pattern: echoPath }],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.analysisOk, command).toBe(true);
      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
      expect(analysis.segmentAllowlistEntries, command).toEqual([null]);
      expect(
        resolveAllowAlwaysPatterns({
          segments: analysis.segments,
          cwd: dir,
          env,
          platform: process.platform,
        }),
        command,
      ).toEqual([]);
    }
  });

  it("blocks allowlisted inner commands through exec context-changing shell carriers", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const okTool = makeExecutable(dir, "ok-tool");
    const otherTool = makeExecutable(dir, "other-tool");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    for (const command of [
      `exec -l bash -c "ok-tool && other-tool"`,
      `exec -a -bash bash -c "ok-tool && other-tool"`,
      `exec -c bash -c "ok-tool && other-tool"`,
    ]) {
      const analysis = evaluateShellAllowlist({
        command,
        allowlist: [{ pattern: okTool }, { pattern: otherTool }],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });

      expect(analysis.allowlistSatisfied, command).toBe(false);
      expect(analysis.exactCommandDurableApprovalAllowed, command).toBe(false);
      expect(
        resolveAllowAlwaysPatterns({
          segments: analysis.segments,
          cwd: dir,
          env,
          platform: process.platform,
        }),
        command,
      ).toEqual([]);
    }
  });

  it("falls back to exact trust for carrier-wrapped simple shell payloads", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    makeExecutable(dir, "ok-tool");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);
    const command = `command sh -c "ok-tool"`;
    const durableEntry = {
      pattern: durableCommandPattern(command, dir),
      source: "allow-always" as const,
    };

    const { analysis, persisted } = resolvePersistedPatterns({
      command,
      dir,
      env,
      safeBins,
    });
    expect(analysis.exactCommandDurableApprovalAllowed).toBe(true);
    expect(persisted).toEqual([]);

    const second = evaluateShellAllowlist({
      command,
      allowlist: [durableEntry],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(second.allowlistSatisfied).toBe(false);
    expect(
      hasDurableExecApproval({
        analysisOk: second.analysisOk,
        segmentAllowlistEntries: second.segmentAllowlistEntries,
        allowlist: [durableEntry],
        commandText: command,
        cwd: dir,
      }),
    ).toBe(true);
  });

  it("does not allowlist carrier binaries for carried shell payloads", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const commandPath = makeExecutable(dir, "command");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const persisted = resolvePersistedPatterns({
      command: `command sh -c 'echo ok'`,
      dir,
      env,
      safeBins,
    });
    expect(persisted.persisted).not.toContain(commandPath);

    const analysis = evaluateShellAllowlist({
      command: `command sh -c 'id > /tmp/pwn'`,
      allowlist: [{ pattern: commandPath }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });

    expect(analysis.allowlistSatisfied).toBe(false);
    expect(analysis.segmentAllowlistEntries).toEqual([null]);
  });

  it("does not unwrap shell builtin carriers for direct argv allowlists", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const commandPath = makeExecutable(dir, "command");
    const echoPath = makeExecutable(dir, "echo");
    const idPath = makeExecutable(dir, "id");
    makeExecutable(dir, "sh");
    const env = makePathEnv(dir);
    const argv = ["command", "sh", "-c", "echo ok && id"];
    const analysis = analyzeArgvCommand({ argv, cwd: dir, env });
    const safeBins = resolveSafeBins(undefined);

    const innerAllowed = evaluateExecAllowlist({
      analysis,
      allowlist: [{ pattern: echoPath }, { pattern: idPath }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(innerAllowed.allowlistSatisfied).toBe(false);
    expect(innerAllowed.segmentAllowlistEntries).toEqual([null]);

    const carrierAllowed = evaluateExecAllowlist({
      analysis,
      allowlist: [{ pattern: commandPath }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(carrierAllowed.allowlistSatisfied).toBe(true);
    expect(
      resolveAllowAlwaysPatterns({
        segments: analysis.segments,
        cwd: dir,
        env,
        platform: process.platform,
      }),
    ).toEqual([commandPath]);
  });

  it("binds shell script operands after clustered POSIX value options", () => {
    if (process.platform === "win32") {
      return;
    }
    const { dir, script, env, safeBins } = createShellScriptFixture();
    makeExecutable(dir, "bash");
    const pipefail = path.join(dir, "pipefail");
    const extglob = path.join(dir, "extglob");
    fs.writeFileSync(pipefail, "echo wrong\n");
    fs.writeFileSync(extglob, "echo wrong\n");

    for (const testCase of [
      { command: "bash -oC pipefail scripts/save_crystal.sh", optionValue: pipefail },
      { command: "bash -OC extglob scripts/save_crystal.sh", optionValue: extglob },
      { command: "bash +oC pipefail scripts/save_crystal.sh", optionValue: pipefail },
    ]) {
      const { persisted } = resolvePersistedPatterns({
        command: testCase.command,
        dir,
        env,
        safeBins,
      });
      expect(persisted).toEqual([script]);

      const optionValueAllowed = evaluateShellAllowlist({
        command: testCase.command,
        allowlist: [{ pattern: testCase.optionValue }],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });
      expect(optionValueAllowed.allowlistSatisfied).toBe(false);

      const scriptAllowed = evaluateShellAllowlist({
        command: testCase.command,
        allowlist: [{ pattern: script }],
        safeBins,
        cwd: dir,
        env,
        platform: process.platform,
      });
      expect(scriptAllowed.allowlistSatisfied).toBe(true);
    }
  });

  it("rejects positional carrier when carried executable is a shell wrapper", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const bashPath = makeExecutable(dir, "bash");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const { persisted } = resolvePersistedPatterns({
      command: `sh -c '$0 "$@"' bash -lc 'echo safe'`,
      dir,
      env,
      safeBins,
    });
    expect(persisted).toEqual([]);

    const second = evaluateShellAllowlist({
      command: `sh -c '$0 "$@"' bash -lc 'id > /tmp/pwned'`,
      allowlist: [{ pattern: bashPath }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(false);
  });

  it("allows positional carriers for unknown carried executables when explicitly allowlisted", () => {
    if (process.platform === "win32") {
      return;
    }
    const dir = makeTempDir();
    const xargsPath = makeExecutable(dir, "xargs");
    const env = makePathEnv(dir);
    const safeBins = resolveSafeBins(undefined);

    const { persisted } = resolvePersistedPatterns({
      command: `sh -c '$0 "$@"' xargs echo SAFE`,
      dir,
      env,
      safeBins,
    });
    expect(persisted).toEqual([]);

    const second = evaluateShellAllowlist({
      command: `sh -c '$0 "$@"' xargs sh -lc 'id > /tmp/pwned'`,
      allowlist: [{ pattern: xargsPath }],
      safeBins,
      cwd: dir,
      env,
      platform: process.platform,
    });
    expect(second.allowlistSatisfied).toBe(true);
  });
});
