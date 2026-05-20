import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExecAllowlistEntry, ExecAsk, ExecSecurity } from "../infra/exec-approvals.js";
import type { ExecApprovalFollowupTarget } from "./bash-tools.exec-host-shared.js";

type EvaluateShellAllowlistResult = ReturnType<
  typeof import("../infra/exec-approvals.js").evaluateShellAllowlist
>;
type HasDurableExecApproval = typeof import("../infra/exec-approvals.js").hasDurableExecApproval;
type PersistAllowAlwaysPatterns =
  typeof import("../infra/exec-approvals.js").persistAllowAlwaysPatterns;
type ResolveExecApprovalsResult = ReturnType<
  typeof import("../infra/exec-approvals.js").resolveExecApprovals
>;
type ResolveExecHostApprovalContextMockResult = {
  approvals: Pick<ResolveExecApprovalsResult, "allowlist" | "file">;
  hostSecurity: ExecSecurity;
  hostAsk: ExecAsk;
  askFallback: ExecSecurity;
};
type StrictInlineEvalBoundary =
  typeof import("./bash-tools.exec-host-shared.js").enforceStrictInlineEvalApprovalBoundary;
type SendExecApprovalFollowupResult =
  typeof import("./bash-tools.exec-host-shared.js").sendExecApprovalFollowupResult;
type BuildExecApprovalFollowupTargetMock = (
  value: ExecApprovalFollowupTarget,
) => ExecApprovalFollowupTarget | null;
type RequiresExecApprovalParams = {
  ask: "always" | "on-miss" | "off";
  security: "full" | "allowlist";
  analysisOk: boolean;
  allowlistSatisfied: boolean;
  durableApprovalSatisfied?: boolean;
};

const INLINE_EVAL_HIT = {
  executable: "python3",
  normalizedExecutable: "python3",
  flag: "-c",
  argv: ["python3", "-c", "print(1)"],
};

const createAndRegisterDefaultExecApprovalRequestMock = vi.hoisted(() => vi.fn());
const buildExecApprovalPendingToolResultMock = vi.hoisted(() => vi.fn());
const registerExecApprovalRequestForHostOrThrowMock = vi.hoisted(() =>
  vi.fn(async () => undefined),
);
const buildExecApprovalFollowupTargetMock = vi.hoisted(() =>
  vi.fn<BuildExecApprovalFollowupTargetMock>(() => null),
);
const createExecApprovalDecisionStateMock = vi.hoisted(() =>
  vi.fn(
    (): {
      baseDecision: { timedOut: boolean };
      approvedByAsk: boolean;
      deniedReason: string | null;
    } => ({
      baseDecision: { timedOut: false },
      approvedByAsk: false,
      deniedReason: "approval-required",
    }),
  ),
);
const evaluateShellAllowlistMock = vi.hoisted(() =>
  vi.fn(
    (): EvaluateShellAllowlistResult => ({
      allowlistMatches: [],
      analysisOk: true,
      allowlistSatisfied: true,
      exactCommandDurableApprovalAllowed: true,
      segments: [{ raw: "echo ok", resolution: null, argv: ["echo", "ok"] }],
      segmentAllowlistEntries: [{ pattern: "/usr/bin/echo", source: "allow-always" }],
      segmentSatisfiedBy: ["allowlist"],
    }),
  ),
);
const hasDurableExecApprovalMock = vi.hoisted(() => vi.fn<HasDurableExecApproval>(() => true));
const requiresExecApprovalMock = vi.hoisted(() =>
  vi.fn((params: RequiresExecApprovalParams): boolean => {
    if (params.ask === "always") {
      return true;
    }
    if (params.durableApprovalSatisfied === true) {
      return false;
    }
    return (
      params.ask === "on-miss" &&
      params.security === "allowlist" &&
      (!params.analysisOk || !params.allowlistSatisfied)
    );
  }),
);
const persistAllowAlwaysPatternsMock = vi.hoisted(() =>
  vi.fn<PersistAllowAlwaysPatterns>(() => []),
);
const resolveAllowAlwaysPatternsMock = vi.hoisted(() => vi.fn((): string[] => []));
const addDurableCommandApprovalMock = vi.hoisted(() => vi.fn());
const buildEnforcedShellCommandMock = vi.hoisted(() =>
  vi.fn((): { ok: boolean; reason?: string; command?: string } => ({
    ok: false,
    reason: "segment execution plan unavailable",
  })),
);
const recordAllowlistMatchesUseMock = vi.hoisted(() => vi.fn());
const resolveApprovalDecisionOrUndefinedMock = vi.hoisted(() =>
  vi.fn(async (): Promise<string | null | undefined> => undefined),
);
const resolveExecApprovalAllowedDecisionsForPersistenceMock = vi.hoisted(() =>
  vi.fn((params: { ask?: string | null; allowAlwaysAvailable: boolean }) => {
    if (params.ask === "always" || !params.allowAlwaysAvailable) {
      return ["allow-once", "deny"];
    }
    return ["allow-once", "allow-always", "deny"];
  }),
);
const resolveExecHostApprovalContextMock = vi.hoisted(() =>
  vi.fn(
    (): ResolveExecHostApprovalContextMockResult => ({
      approvals: { allowlist: [], file: { version: 1, agents: {} } },
      hostSecurity: "allowlist",
      hostAsk: "off",
      askFallback: "deny",
    }),
  ),
);
const runExecProcessMock = vi.hoisted(() => vi.fn());
const sendExecApprovalFollowupResultMock = vi.hoisted(() =>
  vi.fn<SendExecApprovalFollowupResult>(async () => undefined),
);
const enforceStrictInlineEvalApprovalBoundaryMock = vi.hoisted(() =>
  vi.fn<StrictInlineEvalBoundary>((value) => ({
    approvedByAsk: value.approvedByAsk,
    deniedReason: value.deniedReason,
  })),
);
const detectInterpreterInlineEvalArgvMock = vi.hoisted(() =>
  vi.fn(
    (): {
      executable: string;
      normalizedExecutable: string;
      flag: string;
      argv: string[];
    } | null => null,
  ),
);

vi.mock("../infra/exec-approvals.js", () => ({
  evaluateShellAllowlist: evaluateShellAllowlistMock,
  hasDurableExecApproval: hasDurableExecApprovalMock,
  buildEnforcedShellCommand: buildEnforcedShellCommandMock,
  requiresExecApproval: requiresExecApprovalMock,
  recordAllowlistUse: vi.fn(),
  recordAllowlistMatchesUse: recordAllowlistMatchesUseMock,
  resolveApprovalAuditCandidatePath: vi.fn(() => null),
  resolveAllowAlwaysPatterns: resolveAllowAlwaysPatternsMock,
  persistAllowAlwaysPatterns: persistAllowAlwaysPatternsMock,
  resolveExecApprovalAllowedDecisions: vi.fn(() => ["allow-once", "allow-always", "deny"]),
  addAllowlistEntry: vi.fn(),
  addDurableCommandApproval: addDurableCommandApprovalMock,
}));

vi.mock("./bash-tools.exec-approval-request.js", () => ({
  buildExecApprovalRequesterContext: vi.fn(() => ({})),
  buildExecApprovalTurnSourceContext: vi.fn(() => ({})),
  registerExecApprovalRequestForHostOrThrow: registerExecApprovalRequestForHostOrThrowMock,
}));

vi.mock("./bash-tools.exec-host-shared.js", () => ({
  resolveExecHostApprovalContext: resolveExecHostApprovalContextMock,
  buildDefaultExecApprovalRequestArgs: vi.fn(() => ({})),
  buildHeadlessExecApprovalDeniedMessage: vi.fn(() => "denied"),
  buildExecApprovalFollowupTarget: buildExecApprovalFollowupTargetMock,
  buildExecApprovalPendingToolResult: buildExecApprovalPendingToolResultMock,
  createExecApprovalDecisionState: createExecApprovalDecisionStateMock,
  createAndRegisterDefaultExecApprovalRequest: createAndRegisterDefaultExecApprovalRequestMock,
  enforceStrictInlineEvalApprovalBoundary: enforceStrictInlineEvalApprovalBoundaryMock,
  resolveExecApprovalAllowedDecisionsForPersistence:
    resolveExecApprovalAllowedDecisionsForPersistenceMock,
  resolveApprovalDecisionOrUndefined: resolveApprovalDecisionOrUndefinedMock,
  sendExecApprovalFollowupResult: sendExecApprovalFollowupResultMock,
  shouldResolveExecApprovalUnavailableInline: vi.fn(() => false),
}));

vi.mock("./bash-tools.exec-runtime.js", () => ({
  DEFAULT_NOTIFY_TAIL_CHARS: 1000,
  createApprovalSlug: vi.fn(() => "slug"),
  normalizeNotifyOutput: vi.fn((value) => value),
  runExecProcess: runExecProcessMock,
}));

vi.mock("./bash-process-registry.js", () => ({
  markBackgrounded: vi.fn(),
  tail: vi.fn((value) => value),
}));

vi.mock("../infra/command-analysis/inline-eval.js", () => ({
  describeInterpreterInlineEval: vi.fn(() => "python -c"),
  detectInterpreterInlineEvalArgv: detectInterpreterInlineEvalArgvMock,
}));

let processGatewayAllowlist: typeof import("./bash-tools.exec-host-gateway.js").processGatewayAllowlist;
type GatewayAllowlistParams = Parameters<typeof processGatewayAllowlist>[0];

describe("processGatewayAllowlist", () => {
  beforeAll(async () => {
    ({ processGatewayAllowlist } = await import("./bash-tools.exec-host-gateway.js"));
  });

  beforeEach(() => {
    buildExecApprovalPendingToolResultMock.mockReset();
    buildExecApprovalFollowupTargetMock.mockReset();
    buildExecApprovalFollowupTargetMock.mockReturnValue(null);
    createExecApprovalDecisionStateMock.mockReset();
    createExecApprovalDecisionStateMock.mockReturnValue({
      baseDecision: { timedOut: false },
      approvedByAsk: false,
      deniedReason: "approval-required",
    });
    evaluateShellAllowlistMock.mockReset();
    evaluateShellAllowlistMock.mockReturnValue({
      allowlistMatches: [],
      analysisOk: true,
      allowlistSatisfied: true,
      exactCommandDurableApprovalAllowed: true,
      segments: [{ raw: "echo ok", resolution: null, argv: ["echo", "ok"] }],
      segmentAllowlistEntries: [{ pattern: "/usr/bin/echo", source: "allow-always" }],
      segmentSatisfiedBy: ["allowlist"],
    });
    hasDurableExecApprovalMock.mockReset();
    hasDurableExecApprovalMock.mockReturnValue(true);
    requiresExecApprovalMock.mockClear();
    persistAllowAlwaysPatternsMock.mockReset();
    persistAllowAlwaysPatternsMock.mockReturnValue([]);
    resolveAllowAlwaysPatternsMock.mockReset();
    resolveAllowAlwaysPatternsMock.mockReturnValue([]);
    addDurableCommandApprovalMock.mockReset();
    buildEnforcedShellCommandMock.mockReset();
    buildEnforcedShellCommandMock.mockReturnValue({
      ok: false,
      reason: "segment execution plan unavailable",
    });
    recordAllowlistMatchesUseMock.mockReset();
    resolveApprovalDecisionOrUndefinedMock.mockReset();
    resolveApprovalDecisionOrUndefinedMock.mockResolvedValue(undefined);
    resolveExecApprovalAllowedDecisionsForPersistenceMock.mockReset();
    resolveExecApprovalAllowedDecisionsForPersistenceMock.mockImplementation(
      (params: { ask?: string | null; allowAlwaysAvailable: boolean }) => {
        if (params.ask === "always" || !params.allowAlwaysAvailable) {
          return ["allow-once", "deny"];
        }
        return ["allow-once", "allow-always", "deny"];
      },
    );
    resolveExecHostApprovalContextMock.mockReset();
    resolveExecHostApprovalContextMock.mockReturnValue({
      approvals: { allowlist: [], file: { version: 1, agents: {} } },
      hostSecurity: "allowlist",
      hostAsk: "off",
      askFallback: "deny",
    });
    runExecProcessMock.mockReset();
    sendExecApprovalFollowupResultMock.mockReset();
    enforceStrictInlineEvalApprovalBoundaryMock.mockReset();
    enforceStrictInlineEvalApprovalBoundaryMock.mockImplementation((value) => ({
      approvedByAsk: value.approvedByAsk,
      deniedReason: value.deniedReason,
    }));
    detectInterpreterInlineEvalArgvMock.mockReset();
    detectInterpreterInlineEvalArgvMock.mockReturnValue(null);
    registerExecApprovalRequestForHostOrThrowMock.mockReset();
    buildExecApprovalPendingToolResultMock.mockReturnValue({
      details: { status: "approval-pending" },
      content: [],
    });
    createAndRegisterDefaultExecApprovalRequestMock.mockReset();
    createAndRegisterDefaultExecApprovalRequestMock.mockImplementation(async (args?: unknown) => {
      const register =
        args && typeof args === "object" && "register" in args
          ? (args as { register?: (approvalId: string) => Promise<void> }).register
          : undefined;
      await register?.("req-1");
      return {
        approvalId: "req-1",
        approvalSlug: "slug-1",
        warningText: "",
        expiresAtMs: Date.now() + 60_000,
        preResolvedDecision: null,
        initiatingSurface: "origin",
        sentApproverDms: false,
        unavailableReason: null,
      };
    });
  });

  function runGatewayAllowlist(
    overrides: Partial<GatewayAllowlistParams> & Pick<GatewayAllowlistParams, "command">,
  ) {
    const { command, ...rest } = overrides;
    return processGatewayAllowlist({
      command,
      workdir: process.cwd(),
      env: process.env as Record<string, string>,
      pty: false,
      defaultTimeoutSec: 30,
      security: "allowlist",
      ask: "off",
      safeBins: new Set(),
      safeBinProfiles: {},
      warnings: [],
      approvalRunningNoticeMs: 0,
      maxOutput: 1000,
      pendingMaxOutput: 1000,
      ...rest,
    });
  }

  async function runTimedOutStrictInlineEval(params: {
    security: "full" | "allowlist";
    askFallback: "full" | "allowlist";
    approvedByAsk: boolean;
  }) {
    resolveExecHostApprovalContextMock.mockReturnValue({
      approvals: { allowlist: [], file: { version: 1, agents: {} } },
      hostSecurity: params.security,
      hostAsk: "always",
      askFallback: params.askFallback,
    });
    detectInterpreterInlineEvalArgvMock.mockReturnValue(INLINE_EVAL_HIT);
    resolveApprovalDecisionOrUndefinedMock.mockResolvedValue(null);
    createExecApprovalDecisionStateMock.mockReturnValue({
      baseDecision: { timedOut: true },
      approvedByAsk: params.approvedByAsk,
      deniedReason: null,
    });
    enforceStrictInlineEvalApprovalBoundaryMock.mockReturnValue({
      approvedByAsk: false,
      deniedReason: "approval-timeout",
    });

    return runGatewayAllowlist({
      command: "python3 -c 'print(1)'",
      security: params.security,
      ask: "always",
      strictInlineEval: true,
    });
  }

  it("still requires approval when allowlist execution plan is unavailable despite durable trust", async () => {
    const result = await runGatewayAllowlist({
      command: "echo ok",
    });

    expect(createAndRegisterDefaultExecApprovalRequestMock).toHaveBeenCalledTimes(1);
    expect(result.pendingResult?.details.status).toBe("approval-pending");
  });

  it("allows durable exact-command trust to bypass the synchronous allowlist miss", async () => {
    evaluateShellAllowlistMock.mockReturnValue({
      allowlistMatches: [],
      analysisOk: false,
      allowlistSatisfied: false,
      exactCommandDurableApprovalAllowed: true,
      segments: [{ raw: "node --version", resolution: null, argv: ["node", "--version"] }],
      segmentAllowlistEntries: [],
      segmentSatisfiedBy: [],
    });
    hasDurableExecApprovalMock.mockReturnValue(true);
    buildEnforcedShellCommandMock.mockReturnValue({
      ok: true,
      command: "node --version",
    });

    const result = await runGatewayAllowlist({
      command: "node --version",
    });

    expect(createAndRegisterDefaultExecApprovalRequestMock).not.toHaveBeenCalled();
    expect(result).toEqual({ execCommandOverride: undefined });
  });

  it("keeps denying allowlist misses when durable trust does not match", async () => {
    evaluateShellAllowlistMock.mockReturnValue({
      allowlistMatches: [],
      analysisOk: false,
      allowlistSatisfied: false,
      exactCommandDurableApprovalAllowed: true,
      segments: [{ raw: "node --version", resolution: null, argv: ["node", "--version"] }],
      segmentAllowlistEntries: [],
      segmentSatisfiedBy: [],
    });
    hasDurableExecApprovalMock.mockReturnValue(false);

    await expect(
      runGatewayAllowlist({
        command: "node --version",
      }),
    ).rejects.toThrow("exec denied: allowlist miss");
  });

  it("does not use exact durable trust for startup shell gateway commands", async () => {
    const exactDurableEntry: ExecAllowlistEntry = {
      pattern: "=command:0000000000000000",
      source: "allow-always",
    };
    resolveExecHostApprovalContextMock.mockReturnValue({
      approvals: {
        allowlist: [exactDurableEntry],
        file: { version: 1, agents: {} },
      },
      hostSecurity: "allowlist",
      hostAsk: "on-miss",
      askFallback: "allowlist",
    });
    evaluateShellAllowlistMock.mockReturnValue({
      allowlistMatches: [],
      analysisOk: true,
      allowlistSatisfied: false,
      exactCommandDurableApprovalAllowed: false,
      segments: [{ raw: 'bash -lc "echo ok"', resolution: null, argv: ["bash", "-lc", "echo ok"] }],
      segmentAllowlistEntries: [null],
      segmentSatisfiedBy: [null],
    });
    hasDurableExecApprovalMock.mockImplementation(
      (params: { allowlist?: readonly unknown[]; commandText?: string | null }) =>
        params.allowlist !== undefined || params.commandText !== null,
    );

    const result = await runGatewayAllowlist({
      command: 'bash -lc "echo ok"',
      ask: "on-miss",
    });

    expect(hasDurableExecApprovalMock).toHaveBeenCalledWith(
      expect.objectContaining({
        allowlist: undefined,
        commandText: null,
      }),
    );
    expect(createAndRegisterDefaultExecApprovalRequestMock).toHaveBeenCalledTimes(1);
    expect(result.pendingResult?.details.status).toBe("approval-pending");
  });

  it("persists derived allow-always patterns when exact durable trust is disabled", async () => {
    resolveExecHostApprovalContextMock.mockReturnValue({
      approvals: { allowlist: [], file: { version: 1, agents: {} } },
      hostSecurity: "allowlist",
      hostAsk: "on-miss",
      askFallback: "deny",
    });
    evaluateShellAllowlistMock.mockReturnValue({
      allowlistMatches: [],
      analysisOk: true,
      allowlistSatisfied: false,
      exactCommandDurableApprovalAllowed: false,
      segments: [{ raw: "touch marker", resolution: null, argv: ["/usr/bin/touch", "marker"] }],
      segmentAllowlistEntries: [null],
      segmentSatisfiedBy: [null],
    });
    hasDurableExecApprovalMock.mockReturnValue(false);
    persistAllowAlwaysPatternsMock.mockReturnValue([{ pattern: "/usr/bin/touch" }]);
    resolveAllowAlwaysPatternsMock.mockReturnValue(["/usr/bin/touch"]);
    resolveApprovalDecisionOrUndefinedMock.mockResolvedValue("allow-always");
    createExecApprovalDecisionStateMock.mockReturnValue({
      baseDecision: { timedOut: false },
      approvedByAsk: true,
      deniedReason: null,
    });
    runExecProcessMock.mockResolvedValue({
      session: { id: "sess-1" },
      promise: Promise.resolve({
        status: "completed",
        exitCode: 0,
        exitSignal: null,
        durationMs: 1,
        timedOut: false,
        aggregated: "ok",
      }),
    });

    const result = await runGatewayAllowlist({
      command: `sh -c '$0 "$1"' /usr/bin/touch marker`,
      ask: "on-miss",
    });

    expect(result.pendingResult?.details.status).toBe("approval-pending");
    expect(registerExecApprovalRequestForHostOrThrowMock).toHaveBeenCalledWith(
      expect.objectContaining({
        allowedDecisions: ["allow-once", "allow-always", "deny"],
      }),
    );
    expect(buildExecApprovalPendingToolResultMock).toHaveBeenCalledWith(
      expect.objectContaining({
        allowedDecisions: ["allow-once", "allow-always", "deny"],
      }),
    );
    await vi.waitFor(() => {
      expect(runExecProcessMock).toHaveBeenCalledTimes(1);
    });
    expect(persistAllowAlwaysPatternsMock).toHaveBeenCalledWith(
      expect.objectContaining({
        segments: [{ raw: "touch marker", resolution: null, argv: ["/usr/bin/touch", "marker"] }],
      }),
    );
    expect(addDurableCommandApprovalMock).not.toHaveBeenCalled();
  });

  it("does not advertise or accept allow-always for unsafe startup shell gateway approvals", async () => {
    resolveExecHostApprovalContextMock.mockReturnValue({
      approvals: { allowlist: [], file: { version: 1, agents: {} } },
      hostSecurity: "allowlist",
      hostAsk: "on-miss",
      askFallback: "deny",
    });
    evaluateShellAllowlistMock.mockReturnValue({
      allowlistMatches: [],
      analysisOk: true,
      allowlistSatisfied: false,
      exactCommandDurableApprovalAllowed: false,
      segments: [{ raw: "/bin/echo ok", resolution: null, argv: ["/bin/echo", "ok"] }],
      segmentAllowlistEntries: [null],
      segmentSatisfiedBy: [null],
    });
    hasDurableExecApprovalMock.mockReturnValue(false);
    resolveApprovalDecisionOrUndefinedMock.mockResolvedValue("allow-always");
    createExecApprovalDecisionStateMock.mockReturnValue({
      baseDecision: { timedOut: false },
      approvedByAsk: true,
      deniedReason: null,
    });
    runExecProcessMock.mockResolvedValue({
      session: { id: "sess-1" },
      promise: Promise.resolve({
        status: "completed",
        exitCode: 0,
        exitSignal: null,
        durationMs: 1,
        timedOut: false,
        aggregated: "ok",
      }),
    });

    const result = await runGatewayAllowlist({
      command: 'pwsh -Command "/bin/echo ok"',
      ask: "on-miss",
    });

    expect(result.pendingResult?.details.status).toBe("approval-pending");
    expect(registerExecApprovalRequestForHostOrThrowMock).toHaveBeenCalledWith(
      expect.objectContaining({
        allowedDecisions: ["allow-once", "deny"],
      }),
    );
    expect(buildExecApprovalPendingToolResultMock).toHaveBeenCalledWith(
      expect.objectContaining({
        allowedDecisions: ["allow-once", "deny"],
      }),
    );
    await vi.waitFor(() => {
      expect(sendExecApprovalFollowupResultMock).toHaveBeenCalledWith(
        null,
        'Exec denied (gateway id=req-1, approval-decision-unavailable): pwsh -Command "/bin/echo ok"',
      );
    });
    expect(runExecProcessMock).not.toHaveBeenCalled();
    expect(persistAllowAlwaysPatternsMock).not.toHaveBeenCalled();
    expect(addDurableCommandApprovalMock).not.toHaveBeenCalled();
  });

  it("uses sessionKey for followups when notifySessionKey is absent", async () => {
    await runGatewayAllowlist({
      command: "echo ok",
      sessionKey: "agent:main:telegram:direct:123",
    });

    expect(buildExecApprovalFollowupTargetMock).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionKey: "agent:main:telegram:direct:123",
      }),
    );
  });

  it("formats diagnostics approvals as direct pasteable followups", async () => {
    resolveApprovalDecisionOrUndefinedMock.mockResolvedValue("allow-once");
    createExecApprovalDecisionStateMock.mockReturnValue({
      baseDecision: { timedOut: false },
      approvedByAsk: false,
      deniedReason: null,
    });
    const outcome = {
      status: "completed" as const,
      exitCode: 0,
      exitSignal: null,
      durationMs: 12,
      timedOut: false,
      aggregated: JSON.stringify({
        path: "/tmp/openclaw-diagnostics.zip",
        bytes: 1234,
        manifest: {
          generatedAt: "2026-04-28T20:58:29.311Z",
          openclawVersion: "2026.4.27",
          contents: [
            { path: "diagnostics.json", bytes: 100 },
            { path: "summary.md", bytes: 200 },
          ],
          privacy: {
            payloadFree: true,
            rawLogsIncluded: false,
            notes: ["Logs keep operational summaries."],
          },
        },
      }),
    };
    runExecProcessMock.mockResolvedValue({
      session: { id: "sess-1" },
      promise: Promise.resolve(outcome),
    });
    buildExecApprovalFollowupTargetMock.mockImplementation((value) => value);

    const approvalFollowup = vi.fn(async () =>
      [
        "OpenAI Codex harness:",
        "Codex diagnostics sent to OpenAI servers:",
        "Session 1",
        "Channel: telegram",
        "OpenClaw session id: `session-1`",
        "Codex thread id: `thread-1`",
      ].join("\n"),
    );

    await runGatewayAllowlist({
      command: "openclaw gateway diagnostics export --json",
      trigger: "diagnostics",
      approvalFollowupMode: "direct",
      approvalFollowup,
    });

    await vi.waitFor(() => {
      expect(sendExecApprovalFollowupResultMock).toHaveBeenCalled();
    });
    expect(buildExecApprovalFollowupTargetMock).toHaveBeenCalledWith(
      expect.objectContaining({ direct: true }),
    );
    expect(sendExecApprovalFollowupResultMock).toHaveBeenCalledWith(
      expect.objectContaining({ direct: true }),
      expect.stringContaining("Diagnostics export created."),
    );
    const followupText = sendExecApprovalFollowupResultMock.mock.calls[0]?.[1] ?? "";
    expect(followupText).toContain("Path: /tmp/openclaw-diagnostics.zip");
    expect(followupText).toContain("Contents (2 files):");
    expect(followupText).toContain("OpenAI Codex harness:");
    expect(followupText).toContain("Codex diagnostics sent to OpenAI servers:");
    expect(followupText).toContain("Codex thread id: `thread-1`");
    expect(approvalFollowup).toHaveBeenCalledWith(
      expect.objectContaining({
        approvalId: "req-1",
        sessionId: "sess-1",
        trigger: "diagnostics",
        outcome: expect.objectContaining({ status: "completed", exitCode: 0 }),
      }),
    );
  });

  it("denies timed-out inline-eval requests instead of auto-running them", async () => {
    const result = await runTimedOutStrictInlineEval({
      security: "full",
      askFallback: "full",
      approvedByAsk: true,
    });

    expect(result.pendingResult?.details.status).toBe("approval-pending");
    await vi.waitFor(() => {
      expect(sendExecApprovalFollowupResultMock).toHaveBeenCalledWith(
        null,
        "Exec denied (gateway id=req-1, approval-timeout): python3 -c 'print(1)'",
      );
    });
    expect(runExecProcessMock).not.toHaveBeenCalled();
  });

  it("denies allowlist timeout fallback for strict inline-eval commands", async () => {
    const result = await runTimedOutStrictInlineEval({
      security: "allowlist",
      askFallback: "allowlist",
      approvedByAsk: false,
    });

    expect(result.pendingResult?.details.status).toBe("approval-pending");
    await vi.waitFor(() => {
      expect(sendExecApprovalFollowupResultMock).toHaveBeenCalledWith(
        null,
        "Exec denied (gateway id=req-1, approval-timeout): python3 -c 'print(1)'",
      );
    });
    expect(runExecProcessMock).not.toHaveBeenCalled();
  });
});
