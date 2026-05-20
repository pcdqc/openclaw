import Foundation

enum ExecShellWrapperParser {
    struct ParsedShellWrapper {
        let isWrapper: Bool
        let command: String?

        static let notWrapper = ParsedShellWrapper(isWrapper: false, command: nil)
    }

    private enum Kind {
        case posix
        case cmd
        case powershell
    }

    private struct WrapperSpec {
        let kind: Kind
        let names: Set<String>
    }

    private static let posixLongInlineFlags = Set(["--command"])
    private static let posixLongOptionsWithValue = Set(["--init-file", "--rcfile", "--startup-script"])
    private static let powershellInlineFlags = Set(["-c", "-command", "--command"])

    private static let wrapperSpecs: [WrapperSpec] = [
        WrapperSpec(kind: .posix, names: ["ash", "sh", "bash", "zsh", "dash", "ksh", "fish"]),
        WrapperSpec(kind: .cmd, names: ["cmd.exe", "cmd"]),
        WrapperSpec(kind: .powershell, names: ["powershell", "powershell.exe", "pwsh", "pwsh.exe"]),
    ]

    static func extract(command: [String], rawCommand: String?) -> ParsedShellWrapper {
        let trimmedRaw = rawCommand?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let preferredRaw = trimmedRaw.isEmpty ? nil : trimmedRaw
        return self.extract(command: command, preferredRaw: preferredRaw, depth: 0)
    }

    private static func extract(command: [String], preferredRaw: String?, depth: Int) -> ParsedShellWrapper {
        guard depth < ExecEnvInvocationUnwrapper.maxWrapperDepth else {
            return .notWrapper
        }
        guard let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines), !token0.isEmpty else {
            return .notWrapper
        }

        let base0 = ExecCommandToken.basenameLower(token0)
        if base0 == "env" {
            guard let unwrapped = ExecEnvInvocationUnwrapper.unwrap(command) else {
                return .notWrapper
            }
            return self.extract(command: unwrapped, preferredRaw: preferredRaw, depth: depth + 1)
        }

        guard let spec = self.wrapperSpecs.first(where: { $0.names.contains(base0) }) else {
            return .notWrapper
        }
        guard let payload = self.extractPayload(command: command, spec: spec) else {
            return .notWrapper
        }
        let normalized = preferredRaw ?? payload
        return ParsedShellWrapper(isWrapper: true, command: normalized)
    }

    private static func extractPayload(command: [String], spec: WrapperSpec) -> String? {
        switch spec.kind {
        case .posix:
            self.extractPosixInlineCommand(command)
        case .cmd:
            self.extractCmdInlineCommand(command)
        case .powershell:
            self.extractPowerShellInlineCommand(command)
        }
    }

    private static func extractPosixInlineCommand(_ command: [String]) -> String? {
        var sawInlineCommandFlag = false
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token.isEmpty {
                index += 1
                continue
            }
            if token == "--" {
                guard sawInlineCommandFlag, index + 1 < command.count else {
                    return nil
                }
                return self.trimmedNonEmpty(command[index + 1])
            }
            if !token.hasPrefix("-"), !token.hasPrefix("+") {
                return sawInlineCommandFlag ? token : nil
            }
            if token.hasPrefix("--") {
                let optionName = self.optionName(token)
                if self.posixLongInlineFlags.contains(optionName) {
                    if let equals = token.firstIndex(of: "=") {
                        return self.trimmedNonEmpty(String(token[token.index(after: equals)...]))
                    }
                    sawInlineCommandFlag = true
                    index += 1
                    continue
                }
                index += self.posixLongOptionsWithValue.contains(optionName) && !token.contains("=") ? 2 : 1
                continue
            }
            let shortScan = self.readPosixShortOptionScan(token)
            if shortScan.inline {
                sawInlineCommandFlag = true
            }
            index += shortScan.consumesNextArg ? 2 : 1
        }
        return nil
    }

    private static func extractCmdInlineCommand(_ command: [String]) -> String? {
        guard let idx = command
            .firstIndex(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "/c" })
        else {
            return nil
        }
        let tail = command.suffix(from: command.index(after: idx)).joined(separator: " ")
        let payload = tail.trimmingCharacters(in: .whitespacesAndNewlines)
        return payload.isEmpty ? nil : payload
    }

    private static func extractPowerShellInlineCommand(_ command: [String]) -> String? {
        for idx in 1..<command.count {
            let token = command[idx].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if token.isEmpty { continue }
            if token == "--" { break }
            if self.powershellInlineFlags.contains(token) {
                let payload = idx + 1 < command.count
                    ? command[idx + 1].trimmingCharacters(in: .whitespacesAndNewlines)
                    : ""
                return payload.isEmpty ? nil : payload
            }
        }
        return nil
    }

    private static func optionName(_ token: String) -> String {
        token.split(separator: "=", maxSplits: 1).first.map(String.init) ?? token
    }

    private static func trimmedNonEmpty(_ token: String?) -> String? {
        let trimmed = token?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func readPosixShortOptionScan(_ token: String) -> (inline: Bool, consumesNextArg: Bool) {
        guard (token.hasPrefix("-") || token.hasPrefix("+")),
              !token.hasPrefix("--"),
              !token.hasPrefix("++"),
              token != "-",
              token != "+"
        else {
            return (false, false)
        }

        var inline = false
        var consumesNextArg = false
        for flag in token.dropFirst() {
            if token.hasPrefix("-"), flag == "c" {
                inline = true
                continue
            }
            if flag == "o" || flag == "O" {
                consumesNextArg = true
            }
        }
        return (inline, consumesNextArg)
    }
}
