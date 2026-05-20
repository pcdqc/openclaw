import Foundation
import Testing
@testable import OpenClaw

struct ExecHostRequestEvaluatorTests {
    @Test func `validate request rejects empty command`() {
        let request = ExecHostRequest(
            command: [],
            rawCommand: nil,
            cwd: nil,
            env: nil,
            timeoutMs: nil,
            needsScreenRecording: nil,
            agentId: nil,
            sessionKey: nil,
            approvalDecision: nil)
        switch ExecHostRequestEvaluator.validateRequest(request) {
        case .success:
            Issue.record("expected invalid request")
        case let .failure(error):
            #expect(error.code == "INVALID_REQUEST")
            #expect(error.message == "command required")
        }
    }

    @Test func `evaluate requires prompt on allowlist miss without decision`() {
        let context = Self.makeContext(security: .allowlist, ask: .onMiss, allowlistSatisfied: false, skillAllow: false)
        let decision = ExecHostRequestEvaluator.evaluate(context: context, approvalDecision: nil)
        switch decision {
        case .requiresPrompt:
            break
        case .allow:
            Issue.record("expected prompt requirement")
        case let .deny(error):
            Issue.record("unexpected deny: \(error.message)")
        }
    }

    @Test func `evaluate allows allow once decision on allowlist miss`() {
        let context = Self.makeContext(security: .allowlist, ask: .onMiss, allowlistSatisfied: false, skillAllow: false)
        let decision = ExecHostRequestEvaluator.evaluate(context: context, approvalDecision: .allowOnce)
        switch decision {
        case let .allow(approvedByAsk):
            #expect(approvedByAsk)
        case .requiresPrompt:
            Issue.record("expected allow decision")
        case let .deny(error):
            Issue.record("unexpected deny: \(error.message)")
        }
    }

    @Test func `evaluate denies on explicit deny decision`() {
        let context = Self.makeContext(security: .full, ask: .off, allowlistSatisfied: true, skillAllow: false)
        let decision = ExecHostRequestEvaluator.evaluate(context: context, approvalDecision: .deny)
        switch decision {
        case let .deny(error):
            #expect(error.reason == "user-denied")
        case .requiresPrompt:
            Issue.record("expected deny decision")
        case .allow:
            Issue.record("expected deny decision")
        }
    }

    @Test func `evaluate denies unavailable allow always decision`() {
        let context = Self.makeContext(
            security: .allowlist,
            ask: .always,
            allowlistSatisfied: false,
            skillAllow: false,
            allowAlwaysPatterns: ["/usr/bin/echo"])
        let decision = ExecHostRequestEvaluator.evaluate(context: context, approvalDecision: .allowAlways)
        switch decision {
        case let .deny(error):
            #expect(error.reason == "approval-decision-unavailable")
        case .requiresPrompt:
            Issue.record("expected unavailable decision deny")
        case .allow:
            Issue.record("expected unavailable decision deny")
        }
    }

    @Test func `evaluate accepts exact command allow always decision`() {
        let context = Self.makeContext(
            security: .allowlist,
            ask: .onMiss,
            allowlistSatisfied: false,
            skillAllow: false,
            exactCommandDurableApprovalAllowed: true)
        #expect(context.allowAlwaysAvailable)

        let decision = ExecHostRequestEvaluator.evaluate(context: context, approvalDecision: .allowAlways)
        switch decision {
        case let .allow(approvedByAsk):
            #expect(approvedByAsk)
        case .requiresPrompt:
            Issue.record("expected allow decision")
        case let .deny(error):
            Issue.record("unexpected deny: \(error.message)")
        }
    }

    private static func makeContext(
        security: ExecSecurity,
        ask: ExecAsk,
        allowlistSatisfied: Bool,
        skillAllow: Bool,
        allowAlwaysPatterns: [String] = [],
        exactCommandDurableApprovalAllowed: Bool = false) -> ExecApprovalEvaluation
    {
        ExecApprovalEvaluation(
            command: ["/usr/bin/echo", "hi"],
            displayCommand: "/usr/bin/echo hi",
            agentId: nil,
            cwd: nil,
            approvalEnv: nil,
            security: security,
            ask: ask,
            env: [:],
            resolution: nil,
            allowlistResolutions: [],
            allowAlwaysPatterns: allowAlwaysPatterns,
            exactCommandDurableApprovalAllowed: exactCommandDurableApprovalAllowed,
            allowlistMatches: [],
            allowlistSatisfied: allowlistSatisfied,
            allowlistMatch: nil,
            skillAllow: skillAllow)
    }
}
