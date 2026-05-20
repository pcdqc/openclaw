import Foundation
import Testing
@testable import OpenClaw

/// These cases cover optional `security=allowlist` behavior.
/// Default install posture remains deny-by-default for exec on macOS node-host.
struct ExecAllowlistTests {
    private struct ShellParserParityFixture: Decodable {
        struct Case: Decodable {
            let id: String
            let command: String
            let ok: Bool
            let executables: [String]
        }

        let cases: [Case]
    }

    private struct WrapperResolutionParityFixture: Decodable {
        struct Case: Decodable {
            let id: String
            let argv: [String]
            let expectedRawExecutable: String?
        }

        let cases: [Case]
    }

    private static func loadShellParserParityCases() throws -> [ShellParserParityFixture.Case] {
        let fixtureURL = self.fixtureURL(filename: "exec-allowlist-shell-parser-parity.json")
        let data = try Data(contentsOf: fixtureURL)
        let fixture = try JSONDecoder().decode(ShellParserParityFixture.self, from: data)
        return fixture.cases
    }

    private static func loadWrapperResolutionParityCases() throws -> [WrapperResolutionParityFixture.Case] {
        let fixtureURL = self.fixtureURL(filename: "exec-wrapper-resolution-parity.json")
        let data = try Data(contentsOf: fixtureURL)
        let fixture = try JSONDecoder().decode(WrapperResolutionParityFixture.self, from: data)
        return fixture.cases
    }

    private static func fixtureURL(filename: String) -> URL {
        var repoRoot = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 {
            repoRoot.deleteLastPathComponent()
        }
        return repoRoot
            .appendingPathComponent("test")
            .appendingPathComponent("fixtures")
            .appendingPathComponent(filename)
    }

    private static func homebrewRGResolution() -> ExecCommandResolution {
        ExecCommandResolution(
            rawExecutable: "rg",
            resolvedPath: "/opt/homebrew/bin/rg",
            executableName: "rg",
            cwd: nil)
    }

    @Test func `match uses resolved path`() {
        let entry = ExecAllowlistEntry(pattern: "/opt/homebrew/bin/rg")
        let resolution = Self.homebrewRGResolution()
        let match = ExecAllowlistMatcher.match(entries: [entry], resolution: resolution)
        #expect(match?.pattern == entry.pattern)
    }

    @Test func `match accepts basename pattern for PATH resolved executable`() {
        let entry = ExecAllowlistEntry(pattern: "rg")
        let resolution = Self.homebrewRGResolution()
        let match = ExecAllowlistMatcher.match(entries: [entry], resolution: resolution)
        #expect(match?.pattern == entry.pattern)
    }

    @Test func `match accepts basename glob for PATH resolved executable`() {
        let entry = ExecAllowlistEntry(pattern: "r?")
        let resolution = Self.homebrewRGResolution()
        let match = ExecAllowlistMatcher.match(entries: [entry], resolution: resolution)
        #expect(match?.pattern == entry.pattern)
    }

    @Test func `match ignores basename for path selected executable`() {
        let entry = ExecAllowlistEntry(pattern: "echo")
        let relativeResolution = ExecCommandResolution(
            rawExecutable: "./echo",
            resolvedPath: "/tmp/oc-basename/echo",
            executableName: "echo",
            cwd: "/tmp/oc-basename")
        let absoluteResolution = ExecCommandResolution(
            rawExecutable: "/tmp/oc-basename/echo",
            resolvedPath: "/tmp/oc-basename/echo",
            executableName: "echo",
            cwd: "/tmp/oc-basename")
        #expect(ExecAllowlistMatcher.match(entries: [entry], resolution: relativeResolution) == nil)
        #expect(ExecAllowlistMatcher.match(entries: [entry], resolution: absoluteResolution) == nil)
    }

    @Test func `match is case insensitive`() {
        let entry = ExecAllowlistEntry(pattern: "/OPT/HOMEBREW/BIN/RG")
        let resolution = Self.homebrewRGResolution()
        let match = ExecAllowlistMatcher.match(entries: [entry], resolution: resolution)
        #expect(match?.pattern == entry.pattern)
    }

    @Test func `match supports glob star`() {
        let entry = ExecAllowlistEntry(pattern: "/opt/**/rg")
        let resolution = Self.homebrewRGResolution()
        let match = ExecAllowlistMatcher.match(entries: [entry], resolution: resolution)
        #expect(match?.pattern == entry.pattern)
    }

    @Test func `exact command durable approval pattern matches command text`() {
        let command = #"/bin/sh -c "set -e""#
        let pattern = ExecApprovalHelpers.durableCommandApprovalPattern(
            command,
            cwd: "/tmp/project-a",
            env: ["SAFE": "1"])

        #expect(pattern == "=command:3535a6df690905a7")

        let match = ExecApprovalHelpers.exactCommandDurableApprovalMatch(
            entries: [
                ExecAllowlistEntry(pattern: pattern ?? "", source: "allow-always"),
                ExecAllowlistEntry(pattern: "/usr/bin/echo"),
            ],
            commandText: command,
            cwd: "/tmp/project-a",
            env: ["SAFE": "1"])

        #expect(match?.pattern == pattern)
        #expect(ExecApprovalHelpers.exactCommandDurableApprovalMatch(
            entries: [ExecAllowlistEntry(pattern: pattern ?? "", source: "allow-always")],
            commandText: command,
            cwd: "/tmp/project-b",
            env: ["SAFE": "1"]) == nil)
        #expect(ExecApprovalHelpers.exactCommandDurableApprovalMatch(
            entries: [ExecAllowlistEntry(pattern: pattern ?? "", source: "allow-always")],
            commandText: command,
            cwd: "/tmp/project-a",
            env: ["SAFE": "2"]) == nil)
    }

    @Test func `exact command durable approval pattern matches js json bytes for absolute cwd`() {
        let pattern = ExecApprovalHelpers.durableCommandApprovalPattern(
            #"/bin/sh -c "set -e""#,
            cwd: "/Users/example/project",
            env: ["SAFE": "1", "LC_ALL": "C"])

        #expect(pattern == "=command:02416b0db25b6ec7")
    }

    @Test func `normalize incoming drops legacy plaintext command text`() throws {
        let normalized = ExecApprovalsStore.normalizeIncoming(ExecApprovalsFile(
            version: 1,
            socket: nil,
            defaults: nil,
            agents: [
                "main": ExecApprovalsAgent(
                    allowlist: [
                        ExecAllowlistEntry(
                            pattern: "=command:test",
                            source: "allow-always",
                            commandText: "echo secret-token"),
                    ]),
            ]))

        let entry = normalized.agents?["main"]?.allowlist?.first
        #expect(entry?.pattern == "=command:test")
        #expect(entry?.source == "allow-always")
        #expect(entry?.commandText == nil)

        let data = try JSONEncoder().encode(normalized)
        let json = String(decoding: data, as: UTF8.self)
        #expect(!json.contains("commandText"))
        #expect(!json.contains("secret-token"))
    }

    @Test func `exact command durable approval binds canonical shell argv instead of legacy raw text`() async {
        let stateDir = FileManager().temporaryDirectory
            .appendingPathComponent("openclaw-exact-command-\(UUID().uuidString)", isDirectory: true)

        await TestIsolation.withEnvValues(["OPENCLAW_STATE_DIR": stateDir.path]) {
            let command = ["/tmp/bash", "-c", "cd ."]
            let legacyRaw = "cd ."
            let legacyPattern = ExecApprovalHelpers.durableCommandApprovalPattern(legacyRaw)
            let canonicalCommand = ExecCommandFormatter.displayString(for: command)

            #expect(canonicalCommand != legacyRaw)
            ExecApprovalsStore.saveFile(ExecApprovalsFile(
                version: 1,
                socket: nil,
                defaults: ExecApprovalsDefaults(security: .allowlist, ask: .onMiss),
                agents: [
                    "main": ExecApprovalsAgent(
                        allowlist: [ExecAllowlistEntry(pattern: legacyPattern ?? "", source: "allow-always")]),
                ]))

            let evaluation = await ExecApprovalEvaluator.evaluate(
                command: command,
                rawCommand: legacyRaw,
                cwd: nil,
                envOverrides: nil,
                agentId: "main")

            #expect(evaluation.displayCommand == canonicalCommand)
            #expect(evaluation.exactCommandDurableApprovalAllowed)
            #expect(!evaluation.allowlistSatisfied)
            #expect(evaluation.allowlistMatch == nil)
        }
    }

    @Test func `exact command durable approval rejects unsafe shell payloads`() {
        for command in [
            ["/bin/sh", "-c", "echo $(/usr/bin/id)"],
            ["/bin/sh", "-c", "echo \"ok `/usr/bin/id`\""],
            ["/usr/bin/env", "BASH_ENV=/tmp/payload.sh", "bash", "-c", "echo ok"],
            ["/bin/sh", "-c", "$0 \"$1\"", "touch", "marker"],
            ["BASH_ENV=/tmp/payload.sh", "bash", "-c", "echo ok"],
            ["pwsh", "-Command", "echo ok"],
            ["pwsh", "-EncodedCommand", "ZQBjAGgAbwAgAG8AawA="],
            ["fish", "-c", "echo ok"],
            ["zsh", "-c", "echo ok"],
            ["/bin/sh", "-c", #"export BASH_ENV=/tmp/payload && bash -c "echo ok""#],
            ["/bin/sh", "-c", #"unset BASH_ENV && bash -c "echo ok""#],
            ["/bin/sh", "-c", #"BASH_ENV=/tmp/payload command bash -c "echo ok""#],
            ["/bin/sh", "-c", #"BASH_ENV=/tmp/payload exec bash -c "echo ok""#],
            ["cmd.exe", "/c", "echo ok"],
            ["command", "bash", "-lc", "echo ok"],
            ["sudo", "bash", "-c", "echo ok"],
            ["sudo", "sh", "-c", "echo ok"],
            ["sudo", "bash", "-lc", "echo ok"],
            ["sudo", "-E", "bash", "-c", "echo ok"],
            ["sudo", "-i"],
            ["doas", "sh", "-c", "echo ok"],
            ["exec", "-c", "bash", "-c", "echo ok"],
            ["BASH_ENV=/tmp/payload.sh", "zsh", "-f", "-c", "echo ok"],
            ["zsh", "-f", "-c", "echo $(/usr/bin/id)"],
            ["pwsh", "--", "./script.ps1"],
            ["pwsh", "./script.ps1"],
            ["pwsh", "-Fi", "./script.ps1"],
            ["pwsh", "/File", "./script.ps1"],
        ] {
            #expect(!ExecCommandResolution.allowsExactCommandDurableApproval(
                command: command,
                cwd: nil,
                env: ["PATH": "/usr/bin:/bin"]))
        }
    }

    @Test func `exact command durable approval accepts profile-suppressed shell payloads`() {
        for command in [
            ["/bin/bash", "-c", "echo ok"],
            ["pwsh", "-NoProfile", "-Command", "echo ok"],
            ["pwsh", "-NoProfile", "-EncodedCommand", "ZQBjAGgAbwAgAG8AawA="],
            ["fish", "-N", "-c", "echo ok"],
            ["zsh", "-f", "-c", "echo ok"],
            ["cmd.exe", "/d", "/c", "echo ok"],
            ["command", "/bin/bash", "-c", "echo ok"],
        ] {
            #expect(ExecCommandResolution.allowsExactCommandDurableApproval(
                command: command,
                cwd: nil,
            env: ["PATH": "/usr/bin:/bin"]))
        }
    }

    @Test func `allow always patterns unwrap option prefixed POSIX shell payloads`() {
        let patterns = ExecCommandResolution.resolveAllowAlwaysPatterns(
            command: ["zsh", "-f", "-c", "/usr/bin/printf ok"],
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])

        #expect(patterns == ["/usr/bin/printf"])
    }

    @Test func `resolve for allowlist splits shell chains`() {
        let command = ["/bin/sh", "-c", "echo allowlisted && /usr/bin/touch /tmp/openclaw-allowlist-test"]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "echo allowlisted && /usr/bin/touch /tmp/openclaw-allowlist-test",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 2)
        #expect(resolutions[0].executableName == "echo")
        #expect(resolutions[1].executableName == "touch")
    }

    @Test func `resolve for allowlist uses wrapper argv payload even with canonical raw command`() {
        let command = ["/bin/sh", "-c", "echo allowlisted && /usr/bin/touch /tmp/openclaw-allowlist-test"]
        let canonicalRaw = "/bin/sh -c \"echo allowlisted && /usr/bin/touch /tmp/openclaw-allowlist-test\""
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: canonicalRaw,
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 2)
        #expect(resolutions[0].executableName == "echo")
        #expect(resolutions[1].executableName == "touch")
    }

    @Test func `resolve for allowlist rejects unsafe shell transport wrappers`() {
        for command in [
            ["/bin/bash", "-lc", "/usr/bin/echo ok"],
            ["pwsh", "-Command", "/usr/bin/echo ok"],
            ["pwsh", "./script.ps1", "-Command", "Get-Date"],
        ] {
            let resolutions = ExecCommandResolution.resolveForAllowlist(
                command: command,
                rawCommand: nil,
                cwd: nil,
                env: ["PATH": "/usr/bin:/bin"])
            #expect(resolutions.isEmpty)
        }
    }

    @Test func `resolve for allowlist fails closed for env modified shell wrappers`() {
        let command = ["/usr/bin/env", "BASH_ENV=/tmp/payload.sh", "bash", "-lc", "echo allowlisted"]
        let canonicalRaw = "/usr/bin/env BASH_ENV=/tmp/payload.sh bash -lc \"echo allowlisted\""
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: canonicalRaw,
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.isEmpty)
    }

    @Test func `resolve for allowlist fails closed for env dash shell wrappers`() {
        let command = ["/usr/bin/env", "-", "bash", "-lc", "echo allowlisted"]
        let canonicalRaw = "/usr/bin/env - bash -lc \"echo allowlisted\""
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: canonicalRaw,
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.isEmpty)
    }

    @Test func `resolve for allowlist keeps quoted operators in single segment`() {
        let command = ["/bin/sh", "-c", "echo \"a && b\""]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "echo \"a && b\"",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 1)
        #expect(resolutions[0].executableName == "echo")
    }

    @Test func `resolve for allowlist fails closed on command substitution`() {
        let command = ["/bin/sh", "-lc", "echo $(/usr/bin/touch /tmp/openclaw-allowlist-test-subst)"]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "echo $(/usr/bin/touch /tmp/openclaw-allowlist-test-subst)",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.isEmpty)
    }

    @Test func `resolve for allowlist fails closed on quoted command substitution`() {
        let command = ["/bin/sh", "-lc", "echo \"ok $(/usr/bin/touch /tmp/openclaw-allowlist-test-quoted-subst)\""]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "echo \"ok $(/usr/bin/touch /tmp/openclaw-allowlist-test-quoted-subst)\"",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.isEmpty)
    }

    @Test func `resolve for allowlist fails closed on line-continued command substitution`() {
        let command = ["/bin/sh", "-lc", "echo $\\\n(/usr/bin/touch /tmp/openclaw-allowlist-test-line-cont-subst)"]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "echo $\\\n(/usr/bin/touch /tmp/openclaw-allowlist-test-line-cont-subst)",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.isEmpty)
    }

    @Test func `resolve for allowlist fails closed on chained line-continued command substitution`() {
        let command = [
            "/bin/sh",
            "-lc",
            "echo ok && $\\\n(/usr/bin/touch /tmp/openclaw-allowlist-test-chained-line-cont-subst)",
        ]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "echo ok && $\\\n(/usr/bin/touch /tmp/openclaw-allowlist-test-chained-line-cont-subst)",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.isEmpty)
    }

    @Test func `resolve for allowlist fails closed on quoted backticks`() {
        let command = ["/bin/sh", "-lc", "echo \"ok `/usr/bin/id`\""]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "echo \"ok `/usr/bin/id`\"",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.isEmpty)
    }

    @Test func `resolve for allowlist matches shared shell parser fixture`() throws {
        let fixtures = try Self.loadShellParserParityCases()
        for fixture in fixtures {
            let resolutions = ExecCommandResolution.resolveForAllowlist(
                command: ["/bin/sh", "-c", fixture.command],
                rawCommand: fixture.command,
                cwd: nil,
                env: ["PATH": "/usr/bin:/bin"])

            #expect(!resolutions.isEmpty == fixture.ok)
            if fixture.ok {
                let executables = resolutions.map { $0.executableName.lowercased() }
                let expected = fixture.executables.map { $0.lowercased() }
                #expect(executables == expected)
            }
        }
    }

    @Test func `resolve matches shared wrapper resolution fixture`() throws {
        let fixtures = try Self.loadWrapperResolutionParityCases()
        for fixture in fixtures {
            let resolution = ExecCommandResolution.resolve(
                command: fixture.argv,
                cwd: nil,
                env: ["PATH": "/usr/bin:/bin"])
            #expect(resolution?.rawExecutable == fixture.expectedRawExecutable)
        }
    }

    @Test func `resolve keeps env dash wrapper as effective executable`() {
        let resolution = ExecCommandResolution.resolve(
            command: ["/usr/bin/env", "-", "/usr/bin/printf", "ok"],
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolution?.rawExecutable == "/usr/bin/env")
        #expect(resolution?.resolvedPath == "/usr/bin/env")
        #expect(resolution?.executableName == "env")
    }

    @Test func `resolve for allowlist treats plain sh invocation as direct exec`() {
        let command = ["/bin/sh", "./script.sh"]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: nil,
            cwd: "/tmp",
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 1)
        #expect(resolutions[0].executableName == "sh")
    }

    @Test func `resolve for allowlist unwraps env shell wrapper chains`() {
        let command = [
            "/usr/bin/env",
            "/bin/sh",
            "-c",
            "echo allowlisted && /usr/bin/touch /tmp/openclaw-allowlist-test",
        ]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: nil,
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 2)
        #expect(resolutions[0].executableName == "echo")
        #expect(resolutions[1].executableName == "touch")
    }

    @Test func `resolve for allowlist unwraps env dispatch wrappers inside shell segments`() {
        let command = ["/bin/sh", "-c", "env /usr/bin/touch /tmp/openclaw-allowlist-test"]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "env /usr/bin/touch /tmp/openclaw-allowlist-test",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 1)
        #expect(resolutions[0].resolvedPath == "/usr/bin/touch")
        #expect(resolutions[0].executableName == "touch")
    }

    @Test func `resolve for allowlist preserves env assignments inside shell segments`() {
        let command = ["/bin/sh", "-c", "env FOO=bar /usr/bin/touch /tmp/openclaw-allowlist-test"]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: "env FOO=bar /usr/bin/touch /tmp/openclaw-allowlist-test",
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 1)
        #expect(resolutions[0].resolvedPath == "/usr/bin/env")
        #expect(resolutions[0].executableName == "env")
    }

    @Test func `resolve for allowlist preserves env wrapper with modifiers`() {
        let command = ["/usr/bin/env", "FOO=bar", "/usr/bin/printf", "ok"]
        let resolutions = ExecCommandResolution.resolveForAllowlist(
            command: command,
            rawCommand: nil,
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])
        #expect(resolutions.count == 1)
        #expect(resolutions[0].resolvedPath == "/usr/bin/env")
        #expect(resolutions[0].executableName == "env")
    }

    @Test func `approval evaluator resolves shell payload from canonical wrapper text`() async {
        let command = ["/bin/sh", "-c", "/usr/bin/printf ok"]
        let rawCommand = "/bin/sh -c \"/usr/bin/printf ok\""
        let evaluation = await ExecApprovalEvaluator.evaluate(
            command: command,
            rawCommand: rawCommand,
            cwd: nil,
            envOverrides: ["PATH": "/usr/bin:/bin"],
            agentId: nil)

        #expect(evaluation.displayCommand == rawCommand)
        #expect(evaluation.allowlistResolutions.count == 1)
        #expect(evaluation.allowlistResolutions[0].resolvedPath == "/usr/bin/printf")
        #expect(evaluation.allowlistResolutions[0].executableName == "printf")
    }

    @Test func `allow always patterns unwrap env wrapper modifiers to the inner executable`() {
        let patterns = ExecCommandResolution.resolveAllowAlwaysPatterns(
            command: ["/usr/bin/env", "FOO=bar", "/usr/bin/printf", "ok"],
            cwd: nil,
            env: ["PATH": "/usr/bin:/bin"])

        #expect(patterns == ["/usr/bin/printf"])
    }

    @Test func `allow always patterns reject unsafe shell payloads`() {
        for command in [
            ["/bin/sh", "-c", #"bash -lc "echo ok""#],
            ["/bin/sh", "-c", #"export BASH_ENV=/tmp/payload && bash -c "echo ok""#],
            ["/bin/sh", "-c", #"unset BASH_ENV && bash -c "echo ok""#],
            ["sudo", "bash", "-lc", "echo ok"],
            ["exec", "-c", "bash", "-c", "echo ok"],
            ["pwsh", "--", "./script.ps1"],
            ["pwsh", "-Fi", "./script.ps1"],
        ] {
            let patterns = ExecCommandResolution.resolveAllowAlwaysPatterns(
                command: command,
                cwd: nil,
                env: ["PATH": "/usr/bin:/bin"])

            #expect(patterns.isEmpty)
        }
    }

    @Test func `match all requires every segment to match`() {
        let first = ExecCommandResolution(
            rawExecutable: "echo",
            resolvedPath: "/usr/bin/echo",
            executableName: "echo",
            cwd: nil)
        let second = ExecCommandResolution(
            rawExecutable: "/usr/bin/touch",
            resolvedPath: "/usr/bin/touch",
            executableName: "touch",
            cwd: nil)
        let resolutions = [first, second]

        let partial = ExecAllowlistMatcher.matchAll(
            entries: [ExecAllowlistEntry(pattern: "/usr/bin/echo")],
            resolutions: resolutions)
        #expect(partial.isEmpty)

        let full = ExecAllowlistMatcher.matchAll(
            entries: [ExecAllowlistEntry(pattern: "/USR/BIN/ECHO"), ExecAllowlistEntry(pattern: "/usr/bin/touch")],
            resolutions: resolutions)
        #expect(full.count == 2)
    }
}
