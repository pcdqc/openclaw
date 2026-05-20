import AppKit
import Testing
@testable import OpenClaw

@Suite(.serialized)
@MainActor
struct ExecApprovalPromptLayoutTests {
    private func makePromptRequest(
        ask: String? = "on-miss",
        allowedDecisions: [ExecApprovalDecision]? = nil) -> ExecApprovalPromptRequest
    {
        ExecApprovalPromptRequest(
            command: "/bin/sh -lc \"hostname; uptime; echo '---'\"",
            cwd: "/Users/example/projects/openclaw",
            host: "node",
            security: "allowlist",
            ask: ask,
            agentId: "main",
            resolvedPath: "/bin/sh",
            sessionKey: "session-1",
            allowedDecisions: allowedDecisions)
    }

    @Test func `accessory view reserves nonzero alert layout space`() {
        let accessory = ExecApprovalsPromptPresenter.buildAccessoryView(self.makePromptRequest())

        #expect(accessory.frame.width >= 380)
        #expect(accessory.frame.height >= 160)

        let alert = NSAlert()
        alert.messageText = "Allow this command?"
        alert.informativeText = "Review the command details before allowing."
        alert.accessoryView = accessory

        #expect(alert.accessoryView?.frame.width == accessory.frame.width)
        #expect(alert.accessoryView?.frame.height == accessory.frame.height)
    }

    @Test func `prompt decisions honor request scoped decisions and keep deny available`() {
        let decisions = ExecApprovalsPromptPresenter.allowedDecisions(
            for: self.makePromptRequest(allowedDecisions: [.allowOnce]))

        #expect(decisions == [.allowOnce, .deny])
        #expect(decisions.map { ExecApprovalsPromptPresenter.buttonTitle(for: $0) } == [
            "Allow Once",
            "Don't Allow",
        ])
        #expect(
            ExecApprovalsPromptPresenter.decision(
                for: .alertSecondButtonReturn,
                decisions: decisions) == .deny)
    }

    @Test func `prompt decisions default to all decisions when unspecified`() {
        let decisions = ExecApprovalsPromptPresenter.allowedDecisions(for: self.makePromptRequest())

        #expect(decisions == [.allowOnce, .allowAlways, .deny])
    }

    @Test func `prompt decisions hide allow always when ask always`() {
        let decisions = ExecApprovalsPromptPresenter.allowedDecisions(
            for: self.makePromptRequest(ask: "always"))

        #expect(decisions == [.allowOnce, .deny])
    }

    @Test func `prompt decisions ignore explicit allow always when ask always`() {
        let decisions = ExecApprovalsPromptPresenter.allowedDecisions(
            for: self.makePromptRequest(
                ask: "always",
                allowedDecisions: [.allowAlways]))

        #expect(decisions == [.deny])
    }

    @Test func `native prompt decisions hide allow always when persistence is unavailable`() {
        let decisions = ExecApprovalsPromptPresenter.allowedDecisions(
            ask: .onMiss,
            allowAlwaysAvailable: false)

        #expect(decisions == [.allowOnce, .deny])
    }
}
