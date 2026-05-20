import Foundation

struct ExecCommandResolution {
    let rawExecutable: String
    let resolvedPath: String?
    let executableName: String
    let cwd: String?

    static func resolve(
        command: [String],
        rawCommand: String?,
        cwd: String?,
        env: [String: String]?) -> ExecCommandResolution?
    {
        let trimmedRaw = rawCommand?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !trimmedRaw.isEmpty, let token = self.parseFirstToken(trimmedRaw) {
            return self.resolveExecutable(rawExecutable: token, cwd: cwd, env: env)
        }
        return self.resolve(command: command, cwd: cwd, env: env)
    }

    static func resolveForAllowlist(
        command: [String],
        rawCommand: String?,
        cwd: String?,
        env: [String: String]?) -> [ExecCommandResolution]
    {
        // Allowlist resolution must follow actual argv execution for wrappers.
        // `rawCommand` is caller-supplied display text and may be canonicalized.
        let shell = ExecShellWrapperParser.extract(command: command, rawCommand: nil)
        if shell.isWrapper {
            // Fail closed when env modifiers precede a shell wrapper. This mirrors
            // system-run binding behavior where such invocations must stay bound to
            // full argv and must not be auto-allowlisted by payload-only matches.
            if self.blocksShellPayloadAllowlist(command) {
                return []
            }
            guard let shellCommand = shell.command,
                  let segments = self.splitShellCommandChain(shellCommand)
            else {
                // Fail closed: if we cannot safely parse a shell wrapper payload,
                // treat this as an allowlist miss and require approval.
                return []
            }
            var resolutions: [ExecCommandResolution] = []
            resolutions.reserveCapacity(segments.count)
            for segment in segments {
                guard let resolution = self.resolveShellSegmentExecutable(segment, cwd: cwd, env: env)
                else {
                    return []
                }
                resolutions.append(resolution)
            }
            return resolutions
        }

        guard let resolution = self.resolveForAllowlistCommand(
            command: command,
            rawCommand: rawCommand,
            cwd: cwd,
            env: env)
        else {
            return []
        }
        return [resolution]
    }

    static func resolveAllowAlwaysPatterns(
        command: [String],
        cwd: String?,
        env: [String: String]?) -> [String]
    {
        guard self.allowsExactCommandDurableApproval(command: command, cwd: cwd, env: env) else {
            return []
        }

        var patterns: [String] = []
        var seen = Set<String>()
        self.collectAllowAlwaysPatterns(
            command: command,
            cwd: cwd,
            env: env,
            depth: 0,
            patterns: &patterns,
            seen: &seen)
        return patterns
    }

    static func allowsExactCommandDurableApproval(
        command: [String],
        cwd: String?,
        env: [String: String]?) -> Bool
    {
        self.allowsExactCommandDurableApproval(
            command: command,
            cwd: cwd,
            env: env,
            depth: 0)
    }

    static func resolve(command: [String], cwd: String?, env: [String: String]?) -> ExecCommandResolution? {
        let effective = ExecEnvInvocationUnwrapper.unwrapTransparentDispatchWrappersForResolution(command)
        guard let raw = effective.first?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        return self.resolveExecutable(rawExecutable: raw, cwd: cwd, env: env)
    }

    private static func resolveForAllowlistCommand(
        command: [String],
        rawCommand: String?,
        cwd: String?,
        env: [String: String]?) -> ExecCommandResolution?
    {
        let trimmedRaw = rawCommand?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !trimmedRaw.isEmpty, let token = self.parseFirstToken(trimmedRaw) {
            return self.resolveExecutable(rawExecutable: token, cwd: cwd, env: env)
        }
        let effective = ExecEnvInvocationUnwrapper.unwrapDispatchWrappersForResolution(command)
        guard let raw = effective.first?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        return self.resolveExecutable(rawExecutable: raw, cwd: cwd, env: env)
    }

    private static func resolveExecutable(
        rawExecutable: String,
        cwd: String?,
        env: [String: String]?) -> ExecCommandResolution?
    {
        let expanded = rawExecutable.hasPrefix("~") ? (rawExecutable as NSString).expandingTildeInPath : rawExecutable
        let hasPathSeparator = expanded.contains("/") || expanded.contains("\\")
        let resolvedPath: String? = {
            if hasPathSeparator {
                if expanded.hasPrefix("/") {
                    return expanded
                }
                let base = cwd?.trimmingCharacters(in: .whitespacesAndNewlines)
                let root = (base?.isEmpty == false) ? base! : FileManager().currentDirectoryPath
                return URL(fileURLWithPath: root).appendingPathComponent(expanded).path
            }
            let searchPaths = self.searchPaths(from: env)
            return CommandResolver.findExecutable(named: expanded, searchPaths: searchPaths)
        }()
        let name = resolvedPath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? expanded
        return ExecCommandResolution(
            rawExecutable: expanded,
            resolvedPath: resolvedPath,
            executableName: name,
            cwd: cwd)
    }

    private static func resolveShellSegmentExecutable(
        _ segment: String,
        cwd: String?,
        env: [String: String]?) -> ExecCommandResolution?
    {
        let tokens = self.tokenizeShellWords(segment)
        guard !tokens.isEmpty else { return nil }
        let effective = ExecEnvInvocationUnwrapper.unwrapDispatchWrappersForResolution(tokens)
        guard let raw = effective.first?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        return self.resolveExecutable(rawExecutable: raw, cwd: cwd, env: env)
    }

    private static func collectAllowAlwaysPatterns(
        command: [String],
        cwd: String?,
        env: [String: String]?,
        depth: Int,
        patterns: inout [String],
        seen: inout Set<String>)
    {
        guard depth < 3, !command.isEmpty else {
            return
        }

        if let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
           ExecCommandToken.basenameLower(token0) == "env",
           let envUnwrapped = ExecEnvInvocationUnwrapper.unwrap(command),
           !envUnwrapped.isEmpty
        {
            self.collectAllowAlwaysPatterns(
                command: envUnwrapped,
                cwd: cwd,
                env: env,
                depth: depth + 1,
                patterns: &patterns,
                seen: &seen)
            return
        }

        if let shellMultiplexer = self.unwrapShellMultiplexerInvocation(command) {
            self.collectAllowAlwaysPatterns(
                command: shellMultiplexer,
                cwd: cwd,
                env: env,
                depth: depth + 1,
                patterns: &patterns,
                seen: &seen)
            return
        }

        let shell = ExecShellWrapperParser.extract(command: command, rawCommand: nil)
        if shell.isWrapper {
            guard let shellCommand = shell.command,
                  let segments = self.splitShellCommandChain(shellCommand)
            else {
                return
            }
            for segment in segments {
                let tokens = self.tokenizeShellWords(segment)
                guard !tokens.isEmpty else {
                    continue
                }
                self.collectAllowAlwaysPatterns(
                    command: tokens,
                    cwd: cwd,
                    env: env,
                    depth: depth + 1,
                    patterns: &patterns,
                    seen: &seen)
            }
            return
        }

        guard let resolution = self.resolve(command: command, cwd: cwd, env: env),
              let pattern = ExecApprovalHelpers.allowlistPattern(command: command, resolution: resolution),
              seen.insert(pattern).inserted
        else {
            return
        }
        patterns.append(pattern)
    }

    private static func allowsExactCommandDurableApproval(
        command: [String],
        cwd: String?,
        env: [String: String]?,
        depth: Int) -> Bool
    {
        guard depth < 3, !command.isEmpty else {
            return false
        }

        if self.blocksShellPayloadAllowlist(command) {
            return false
        }

        if let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
           ExecCommandToken.basenameLower(token0) == "env",
           let envUnwrapped = ExecEnvInvocationUnwrapper.unwrapWithMetadata(command),
           !envUnwrapped.command.isEmpty
        {
            if envUnwrapped.usesModifiers, self.containsShellWrapper(command: envUnwrapped.command) {
                return false
            }
            return self.allowsExactCommandDurableApproval(
                command: envUnwrapped.command,
                cwd: cwd,
                env: env,
                depth: depth + 1)
        }

        if let shellMultiplexer = self.unwrapShellMultiplexerInvocation(command) {
            return self.allowsExactCommandDurableApproval(
                command: shellMultiplexer,
                cwd: cwd,
                env: env,
                depth: depth + 1)
        }

        if let carrier = self.unwrapExactApprovalCarrierInvocation(command) {
            if carrier.argv.isEmpty || carrier.shellStartupContext {
                return false
            }
            if carrier.environmentContextSeen, self.containsShellWrapper(command: carrier.argv) {
                return false
            }
            return self.allowsExactCommandDurableApproval(
                command: carrier.argv,
                cwd: cwd,
                env: env,
                depth: depth + 1)
        }

        let shellCommand = self.extractShellWrapperInlineCommandForExactApproval(command)
        guard shellCommand != nil else {
            return true
        }
        guard let shellCommand,
              !self.isDirectShellPositionalCarrierInvocation(shellCommand),
              let segments = self.splitShellCommandChain(shellCommand)
        else {
            return false
        }
        if self.shellSegmentsHaveEnvironmentMutationBeforeShellWrapper(segments) {
            return false
        }
        for segment in segments {
            let tokens = self.tokenizeShellWords(segment)
            guard !tokens.isEmpty,
                  self.allowsExactCommandDurableApproval(
                      command: tokens,
                      cwd: cwd,
                      env: env,
                      depth: depth + 1)
            else {
                return false
            }
        }
        return true
    }

    private static func blocksShellPayloadAllowlist(_ command: [String]) -> Bool {
        ExecSystemRunCommandValidator.hasEnvManipulationBeforeShellWrapper(command) ||
            self.hasPolicyBlockedCarrierBeforeShellWrapperInvocation(command) ||
            self.hasSudoShellStartupContextBeforeCarriedCommand(command) ||
            self.hasShellAssignmentPrefixBeforeShellWrapperInvocation(command) ||
            self.hasShellStartupOptionBeforeCommandOperand(command)
    }

    private static func containsShellWrapper(command: [String]) -> Bool {
        guard let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token0.isEmpty
        else {
            return false
        }
        return self.isShellWrapperExecutable(ExecCommandToken.basenameLower(token0)) ||
            ExecShellWrapperParser.extract(command: command, rawCommand: nil).isWrapper
    }

    private static func containsShellWrapperThroughCarriers(command: [String], depth: Int = 0) -> Bool {
        guard depth < 3, !command.isEmpty else {
            return false
        }
        if self.containsShellWrapper(command: command) {
            return true
        }
        if let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
           ExecCommandToken.basenameLower(token0) == "env",
           let envUnwrapped = ExecEnvInvocationUnwrapper.unwrapWithMetadata(command),
           !envUnwrapped.command.isEmpty
        {
            return self.containsShellWrapperThroughCarriers(
                command: envUnwrapped.command,
                depth: depth + 1)
        }
        if let shellMultiplexer = self.unwrapShellMultiplexerInvocation(command) {
            return self.containsShellWrapperThroughCarriers(
                command: shellMultiplexer,
                depth: depth + 1)
        }
        if let carrier = self.unwrapExactApprovalCarrierInvocation(command), !carrier.argv.isEmpty {
            return self.containsShellWrapperThroughCarriers(
                command: carrier.argv,
                depth: depth + 1)
        }
        return false
    }

    private static let shellEnvironmentMutatingBuiltins = Set([
        ".",
        "declare",
        "eval",
        "export",
        "readonly",
        "set",
        "source",
        "typeset",
        "unset",
    ])

    private static func resolveShellEnvironmentMutationCommand(_ command: [String]) -> [String] {
        var current = command
        while let token0 = current.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token0.isEmpty
        {
            let executable = ExecCommandToken.basenameLower(token0)
            if executable == "builtin" {
                current = Array(current.dropFirst())
                continue
            }
            if executable == "command",
               let unwrapped = self.unwrapCommandBuiltinInvocation(current),
               !unwrapped.isEmpty
            {
                current = unwrapped
                continue
            }
            return current
        }
        return current
    }

    private static func shellSegmentMayMutateEnvironment(_ command: [String]) -> Bool {
        let resolved = self.resolveShellEnvironmentMutationCommand(command)
        guard let firstToken = resolved.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !firstToken.isEmpty
        else {
            return false
        }
        if self.isEnvAssignmentToken(firstToken) {
            return true
        }
        let executable = ExecCommandToken.basenameLower(firstToken)
        guard self.shellEnvironmentMutatingBuiltins.contains(executable) else {
            return false
        }
        return resolved.dropFirst().contains { token in
            let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
            return !trimmed.isEmpty && trimmed != "--" && !trimmed.hasPrefix("-")
        }
    }

    private static func shellSegmentsHaveEnvironmentMutationBeforeShellWrapper(_ segments: [String]) -> Bool {
        var shellEnvironmentMutated = false
        for segment in segments {
            let tokens = self.tokenizeShellWords(segment)
            guard !tokens.isEmpty else {
                continue
            }
            if shellEnvironmentMutated,
               self.containsShellWrapperThroughCarriers(command: tokens)
            {
                return true
            }
            if self.shellSegmentMayMutateEnvironment(tokens) {
                shellEnvironmentMutated = true
            }
        }
        return false
    }

    private static func isShellWrapperExecutable(_ executable: String) -> Bool {
        [
            "ash",
            "bash",
            "cmd",
            "cmd.exe",
            "dash",
            "fish",
            "ksh",
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
            "sh",
            "zsh",
        ].contains(executable)
    }

    private static func extractShellWrapperInlineCommandForExactApproval(_ command: [String]) -> String? {
        guard let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token0.isEmpty
        else {
            return nil
        }
        let wrapper = ExecCommandToken.basenameLower(token0)
        if wrapper == "cmd" || wrapper == "cmd.exe" {
            return self.extractCmdInlineCommand(command)
        }
        if ["powershell", "powershell.exe", "pwsh", "pwsh.exe"].contains(wrapper) {
            return self.extractPowerShellInlineCommandForExactApproval(command)
        }
        guard ["ash", "bash", "dash", "fish", "ksh", "sh", "zsh"].contains(wrapper) else {
            return nil
        }
        return self.extractPosixShellInlineCommandForExactApproval(command)
    }

    private static func extractPosixShellInlineCommandForExactApproval(_ command: [String]) -> String? {
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token.isEmpty {
                index += 1
                continue
            }
            if token == "--" || token == "-" {
                return nil
            }
            if token.hasPrefix("--") {
                let optionName = self.optionName(token)
                if optionName == "--command" {
                    return self.inlineOptionPayload(command: command, index: index)
                }
                if [
                    "--init-file",
                    "--rcfile",
                    "--startup-file",
                    "--startup-script",
                ].contains(optionName), !token.contains("=") {
                    index += 2
                } else {
                    index += 1
                }
                continue
            }
            if token.hasPrefix("-") || token.hasPrefix("+") {
                let shortScan = self.readPosixShortOptionScan(token)
                if shortScan.inline {
                    let operandIndex = self.combinedPosixInlineCommandOperandIndex(
                        token: token,
                        tokenIndex: index)
                    guard operandIndex < command.count else { return nil }
                    let payload = command[operandIndex].trimmingCharacters(in: .whitespacesAndNewlines)
                    return payload.isEmpty ? nil : payload
                }
                index += shortScan.consumesNextArg ? 2 : 1
                continue
            }
            return nil
        }
        return nil
    }

    private static func inlineOptionPayload(command: [String], index: Int) -> String? {
        let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
        if let equalsIndex = token.firstIndex(of: "=") {
            let payload = token[token.index(after: equalsIndex)...]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return payload.isEmpty ? nil : String(payload)
        }
        guard index + 1 < command.count else {
            return nil
        }
        let payload = command[index + 1].trimmingCharacters(in: .whitespacesAndNewlines)
        return payload.isEmpty ? nil : payload
    }

    private static func combinedPosixInlineCommandOperandIndex(token: String, tokenIndex: Int) -> Int {
        var extraValueOperandCount = 0
        for flag in token.dropFirst() where flag == "o" || flag == "O" {
            extraValueOperandCount += 1
        }
        return tokenIndex + 1 + extraValueOperandCount
    }

    private static func extractCmdInlineCommand(_ command: [String]) -> String? {
        guard let inlineIndex = command.firstIndex(where: {
            let token = $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return token == "/c" || token == "/k"
        }) else {
            return nil
        }
        let payload = command[(inlineIndex + 1)...]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        return payload.isEmpty ? nil : payload
    }

    private static let powerShellCommandTextOptions = Set(["-c", "-command", "--command"])
    private static let powerShellCommandPayloadOptions =
        powerShellCommandTextOptions.union(["-e", "-en", "-enc", "-encodedcommand"])

    private static func extractPowerShellInlineCommandForExactApproval(_ command: [String]) -> String? {
        guard let match = self.findPowerShellCommandPayloadMatch(command) else {
            return nil
        }
        let flagToken = command[match.flagIndex].trimmingCharacters(in: .whitespacesAndNewlines)
        let optionName = self.powerShellOptionName(flagToken)
        let payload: String
        if let equalsIndex = flagToken.firstIndex(of: "=") {
            payload = String(flagToken[flagToken.index(after: equalsIndex)...])
        } else {
            payload = command[match.valueIndex].trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard !payload.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        if self.powerShellCommandTextOptions.contains(optionName) {
            return ([payload] + command[(match.valueIndex + 1)...])
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: " ")
        }
        return payload.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func isEnvAssignmentToken(_ token: String) -> Bool {
        token.range(of: #"^[A-Za-z_][A-Za-z0-9_]*=.*"#, options: .regularExpression) != nil
    }

    private static func hasShellAssignmentPrefixBeforeShellWrapperInvocation(_ command: [String]) -> Bool {
        var index = 0
        while index < command.count,
              self.isEnvAssignmentToken(command[index].trimmingCharacters(in: .whitespacesAndNewlines))
        {
            index += 1
        }
        guard index > 0, index < command.count else {
            return false
        }
        return self.containsShellWrapperThroughCarriers(command: Array(command[index...]))
    }

    private struct ExactApprovalCarrierInvocation {
        let argv: [String]
        let environmentContextSeen: Bool
        let shellStartupContext: Bool
    }

    private static func unwrapExactApprovalCarrierInvocation(
        _ command: [String]) -> ExactApprovalCarrierInvocation?
    {
        guard let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token0.isEmpty
        else {
            return nil
        }
        switch ExecCommandToken.basenameLower(token0) {
        case "command", "builtin":
            guard let argv = self.unwrapCommandBuiltinInvocation(command), !argv.isEmpty else {
                return nil
            }
            return ExactApprovalCarrierInvocation(
                argv: argv,
                environmentContextSeen: false,
                shellStartupContext: false)
        case "sudo":
            return self.unwrapSudoLikeInvocation(
                command,
                optionsWithValue: self.sudoOptionsWithValue,
                standaloneOptions: self.sudoStandaloneOptions,
                nonExecutingOptions: self.sudoNonExecutingOptions,
                shellStartupOptions: self.sudoShellStartupOptions,
                environmentContextOptions: self.sudoEnvironmentOptions,
                stripsLeadingEnvAssignments: true)
        case "doas":
            return self.unwrapSudoLikeInvocation(
                command,
                optionsWithValue: self.doasOptionsWithValue,
                standaloneOptions: self.doasStandaloneOptions,
                nonExecutingOptions: [],
                shellStartupOptions: self.doasShellStartupOptions,
                environmentContextOptions: [],
                stripsLeadingEnvAssignments: false)
        case "exec":
            return self.unwrapExecInvocation(command)
        default:
            return nil
        }
    }

    private static let commandQueryOptions = Set(["-v", "-V"])
    private static let commandExecutingOptions = Set(["-p"])
    private static let sudoOptionsWithValue = Set([
        "-C",
        "-D",
        "-g",
        "-h",
        "-p",
        "-R",
        "-T",
        "-U",
        "-u",
        "--chdir",
        "--chroot",
        "--close-from",
        "--command-timeout",
        "--group",
        "--host",
        "--other-user",
        "--prompt",
        "--role",
        "--type",
        "--user",
    ])
    private static let sudoStandaloneOptions = Set([
        "-A",
        "-B",
        "-b",
        "-E",
        "-H",
        "-i",
        "-k",
        "-N",
        "-n",
        "-P",
        "-S",
        "-s",
        "--askpass",
        "--background",
        "--bell",
        "--login",
        "--no-update",
        "--non-interactive",
        "--preserve-env",
        "--preserve-groups",
        "--reset-home",
        "--reset-timestamp",
        "--set-home",
        "--shell",
        "--stdin",
    ])
    private static let sudoNonExecutingOptions = Set([
        "-K",
        "-l",
        "-V",
        "-v",
        "-e",
        "--edit",
        "--help",
        "--list",
        "--remove-timestamp",
        "--validate",
        "--version",
    ])
    private static let sudoShellStartupOptions = Set(["-i", "--login", "-s", "--shell"])
    private static let sudoEnvironmentOptions = Set(["-E", "--preserve-env"])
    private static let doasOptionsWithValue = Set(["-a", "-C", "-u"])
    private static let doasStandaloneOptions = Set(["-L", "-n", "-s"])
    private static let doasShellStartupOptions = Set(["-s"])

    private struct ParsedCarrierOption {
        let name: String
        let hasInlineValue: Bool
    }

    private static func parseCarrierOptionToken(
        _ token: String,
        standaloneOptions: Set<String>,
        optionsWithValue: Set<String>,
        nonExecutingOptions: Set<String> = []) -> [ParsedCarrierOption]?
    {
        if token.hasPrefix("--") {
            let name = self.optionName(token)
            guard standaloneOptions.contains(name) ||
                optionsWithValue.contains(name) ||
                nonExecutingOptions.contains(name)
            else {
                return nil
            }
            return [ParsedCarrierOption(name: name, hasInlineValue: token.contains("="))]
        }

        guard token.range(of: #"^-[A-Za-z0-9]"#, options: .regularExpression) != nil else {
            return nil
        }
        var parsed: [ParsedCarrierOption] = []
        let flags = Array(token.dropFirst())
        for (offset, flag) in flags.enumerated() {
            let name = "-\(flag)"
            if optionsWithValue.contains(name) {
                parsed.append(ParsedCarrierOption(
                    name: name,
                    hasInlineValue: offset < flags.count - 1))
                return parsed
            }
            if standaloneOptions.contains(name) || nonExecutingOptions.contains(name) {
                parsed.append(ParsedCarrierOption(name: name, hasInlineValue: false))
                continue
            }
            return nil
        }
        return parsed.isEmpty ? nil : parsed
    }

    private static func carrierOptionConsumesNextValue(
        _ options: [ParsedCarrierOption],
        optionsWithValue: Set<String>,
        nonExecutingOptions: Set<String> = []) -> Bool?
    {
        var consumesNextValue = false
        for option in options {
            if nonExecutingOptions.contains(option.name) {
                return nil
            }
            if optionsWithValue.contains(option.name) {
                consumesNextValue = !option.hasInlineValue
            }
        }
        return consumesNextValue
    }

    private static func unwrapCommandBuiltinInvocation(_ command: [String]) -> [String]? {
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token == "--" {
                return index + 1 < command.count ? Array(command[(index + 1)...]) : nil
            }
            if !token.hasPrefix("-") {
                return Array(command[index...])
            }
            let optionName = self.optionName(token)
            if self.commandQueryOptions.contains(optionName) {
                return nil
            }
            if !self.commandExecutingOptions.contains(optionName) {
                return nil
            }
            index += 1
        }
        return nil
    }

    private static func unwrapSudoLikeInvocation(
        _ command: [String],
        optionsWithValue: Set<String>,
        standaloneOptions: Set<String>,
        nonExecutingOptions: Set<String>,
        shellStartupOptions: Set<String>,
        environmentContextOptions: Set<String>,
        stripsLeadingEnvAssignments: Bool) -> ExactApprovalCarrierInvocation?
    {
        var environmentContextSeen = false
        var shellStartupContext = false
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token == "--" {
                return self.finishSudoLikeCarriedCommand(
                    Array(command[(index + 1)...]),
                    environmentContextSeen: environmentContextSeen,
                    shellStartupContext: shellStartupContext,
                    stripsLeadingEnvAssignments: stripsLeadingEnvAssignments)
            }
            if !token.hasPrefix("-") {
                return self.finishSudoLikeCarriedCommand(
                    Array(command[index...]),
                    environmentContextSeen: environmentContextSeen,
                    shellStartupContext: shellStartupContext,
                    stripsLeadingEnvAssignments: stripsLeadingEnvAssignments)
            }
            guard let parsedOptions = self.parseCarrierOptionToken(
                token,
                standaloneOptions: standaloneOptions,
                optionsWithValue: optionsWithValue,
                nonExecutingOptions: nonExecutingOptions),
                let consumesNextValue = self.carrierOptionConsumesNextValue(
                    parsedOptions,
                    optionsWithValue: optionsWithValue,
                    nonExecutingOptions: nonExecutingOptions)
            else {
                return nil
            }
            if parsedOptions.contains(where: { environmentContextOptions.contains($0.name) }) {
                environmentContextSeen = true
            }
            if parsedOptions.contains(where: { shellStartupOptions.contains($0.name) }) {
                shellStartupContext = true
            }
            index += consumesNextValue ? 2 : 1
        }
        return shellStartupContext
            ? ExactApprovalCarrierInvocation(
                argv: [],
                environmentContextSeen: environmentContextSeen,
                shellStartupContext: true)
            : nil
    }

    private static func finishSudoLikeCarriedCommand(
        _ argv: [String],
        environmentContextSeen: Bool,
        shellStartupContext: Bool,
        stripsLeadingEnvAssignments: Bool) -> ExactApprovalCarrierInvocation?
    {
        var commandIndex = 0
        if stripsLeadingEnvAssignments {
            while commandIndex < argv.count,
                  self.isEnvAssignmentToken(argv[commandIndex].trimmingCharacters(in: .whitespacesAndNewlines))
            {
                commandIndex += 1
            }
        }
        if commandIndex < argv.count {
            return ExactApprovalCarrierInvocation(
                argv: Array(argv[commandIndex...]),
                environmentContextSeen: environmentContextSeen || commandIndex > 0,
                shellStartupContext: shellStartupContext)
        }
        return shellStartupContext
            ? ExactApprovalCarrierInvocation(
                argv: [],
                environmentContextSeen: environmentContextSeen || commandIndex > 0,
                shellStartupContext: true)
            : nil
    }

    private static func unwrapExecInvocation(_ command: [String]) -> ExactApprovalCarrierInvocation? {
        var argv0Changed = false
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token == "--" {
                return index + 1 < command.count
                    ? ExactApprovalCarrierInvocation(
                        argv: Array(command[(index + 1)...]),
                        environmentContextSeen: argv0Changed,
                        shellStartupContext: false)
                    : nil
            }
            if !token.hasPrefix("-") {
                return ExactApprovalCarrierInvocation(
                    argv: Array(command[index...]),
                    environmentContextSeen: argv0Changed,
                    shellStartupContext: false)
            }
            guard let parsedOptions = self.parseCarrierOptionToken(
                token,
                standaloneOptions: ["-c", "-l"],
                optionsWithValue: ["-a"]),
                let consumesNextValue = self.carrierOptionConsumesNextValue(
                    parsedOptions,
                    optionsWithValue: ["-a"])
            else {
                return nil
            }
            if parsedOptions.contains(where: { $0.name == "-a" || $0.name == "-c" || $0.name == "-l" }) {
                argv0Changed = true
            }
            index += consumesNextValue ? 2 : 1
        }
        return nil
    }

    private static func hasSudoShellStartupContextBeforeCarriedCommand(_ command: [String]) -> Bool {
        guard let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token0.isEmpty
        else {
            return false
        }
        let executable = ExecCommandToken.basenameLower(token0)
        guard executable == "sudo" || executable == "doas" else {
            return false
        }
        let carrier = self.unwrapExactApprovalCarrierInvocation(command)
        return carrier?.shellStartupContext == true
    }

    private static func hasPolicyBlockedCarrierBeforeShellWrapperInvocation(
        _ command: [String],
        depth: Int = 0) -> Bool
    {
        guard depth < 3,
              let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token0.isEmpty
        else {
            return false
        }

        let executable = ExecCommandToken.basenameLower(token0)
        if executable == "sudo" || executable == "doas" {
            guard let carrier = self.unwrapExactApprovalCarrierInvocation(command),
                  !carrier.argv.isEmpty
            else {
                return false
            }
            return self.containsShellWrapperThroughCarriers(command: carrier.argv)
        }

        guard let carrier = self.unwrapExactApprovalCarrierInvocation(command),
              !carrier.argv.isEmpty
        else {
            return false
        }
        return self.hasPolicyBlockedCarrierBeforeShellWrapperInvocation(
            carrier.argv,
            depth: depth + 1)
    }

    private static func hasShellStartupOptionBeforeCommandOperand(_ command: [String]) -> Bool {
        guard let token0 = command.first?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token0.isEmpty
        else {
            return false
        }
        let wrapper = ExecCommandToken.basenameLower(token0)
        if wrapper == "cmd" || wrapper == "cmd.exe" {
            return self.hasCmdStartupContextBeforeInlineCommand(command)
        }
        if ["powershell", "powershell.exe", "pwsh", "pwsh.exe"].contains(wrapper) {
            return self.hasPowerShellFileExecutionBeforeCommandPayload(command) ||
                self.hasPowerShellStartupContextBeforeInlineCommand(command)
        }
        if wrapper == "fish" {
            return self.hasFishStartupCommandOptionBeforeCommandOperand(command)
        }
        guard ["ash", "bash", "dash", "fish", "ksh", "sh", "zsh"].contains(wrapper) else {
            return false
        }

        let tracksZshRcs = wrapper == "zsh"
        var zshRcsEnabled = tracksZshRcs
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token.isEmpty {
                index += 1
                continue
            }
            if token == "--" || token == "-" {
                return zshRcsEnabled
            }
            let optionName = self.optionName(token)
            if tracksZshRcs {
                let zshState = self.updateZshRcsState(
                    command: command,
                    index: index,
                    rcsEnabled: zshRcsEnabled)
                zshRcsEnabled = zshState.rcsEnabled
                if zshState.consumedNextArg {
                    index += 2
                    continue
                }
            }
            if [
                "--init-file",
                "--login",
                "--rcfile",
                "--startup-file",
                "--startup-script",
            ].contains(optionName) {
                return true
            }
            if optionName == "--command" {
                return zshRcsEnabled
            }
            if [
                "--init-file",
                "--rcfile",
                "--startup-script",
            ].contains(optionName), !token.contains("=") {
                index += 2
                continue
            }
            if !token.hasPrefix("-"), !token.hasPrefix("+") {
                return zshRcsEnabled
            }
            if token.hasPrefix("--") || token.hasPrefix("++") {
                index += 1
                continue
            }
            let shortScan = self.readPosixShortOptionScan(token)
            if shortScan.startup {
                return true
            }
            if shortScan.inline {
                return zshRcsEnabled
            }
            if shortScan.consumesNextArg {
                index += 2
            } else {
                index += 1
            }
        }
        return zshRcsEnabled
    }

    private static func hasFishStartupCommandOptionBeforeCommandOperand(_ command: [String]) -> Bool {
        var noConfig = false
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token.isEmpty {
                index += 1
                continue
            }
            if token == "--" || !token.hasPrefix("-") {
                return !noConfig
            }
            if token.hasPrefix("--") {
                let optionName = self.optionName(token)
                if optionName == "--init-command" {
                    return true
                }
                if optionName == "--no-config" {
                    noConfig = true
                    index += 1
                    continue
                }
                if optionName == "--command" {
                    return !noConfig
                }
                if [
                    "--debug",
                    "--debug-output",
                    "--debug-stack-frames",
                    "--features",
                    "--profile",
                    "--profile-startup",
                ].contains(optionName), !token.contains("=") {
                    index += 2
                } else {
                    index += 1
                }
                continue
            }

            let shortScan = self.readFishShortCommandOption(token)
            if shortScan.noConfig {
                noConfig = true
            }
            if shortScan.startup {
                return true
            }
            if shortScan.inline {
                return !noConfig
            }
            if shortScan.consumesNextArg {
                index += 2
            } else {
                index += 1
            }
        }
        return !noConfig
    }

    private static func hasCmdStartupContextBeforeInlineCommand(_ command: [String]) -> Bool {
        guard let inlineIndex = command.firstIndex(where: {
            let token = $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return token == "/c" || token == "/k"
        }) else {
            return false
        }
        for index in 1..<inlineIndex {
            if command[index].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "/d" {
                return false
            }
        }
        return true
    }

    private static func hasPowerShellFileExecutionBeforeCommandPayload(_ command: [String]) -> Bool {
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if token.isEmpty {
                index += 1
                continue
            }
            let optionName = self.powerShellOptionName(token)
            if self.isPowerShellFileExecutionOption(token) {
                return true
            }
            if self.powerShellCommandPayloadOptions.contains(optionName) {
                return false
            }
            if optionName == "--" {
                guard index + 1 < command.count else {
                    return false
                }
                return !command[index + 1].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            }
            if self.powerShellOptionConsumesNextArg(token) {
                index += 2
                continue
            }
            if optionName.hasPrefix("-") || self.isKnownPowerShellSlashOption(token) {
                index += 1
                continue
            }
            return true
        }
        return false
    }

    private static func hasPowerShellStartupContextBeforeInlineCommand(_ command: [String]) -> Bool {
        guard let match = self.findPowerShellCommandPayloadMatch(command) else {
            return false
        }
        var profilesDisabled = false
        var loginShell = false
        var index = 1
        while index < match.flagIndex {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            if self.isPowerShellLoginOption(token) {
                loginShell = true
            } else if self.isPowerShellDisableProfileOption(token) {
                profilesDisabled = true
            }
            if self.powerShellOptionConsumesNextArg(token) {
                index += 2
            } else {
                index += 1
            }
        }
        return loginShell || !profilesDisabled
    }

    private static func findPowerShellCommandPayloadMatch(_ command: [String]) -> (flagIndex: Int, valueIndex: Int)? {
        var index = 1
        while index < command.count {
            let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
            let optionName = self.powerShellOptionName(token)
            if [
                "-c",
                "-command",
                "--command",
                "-e",
                "-en",
                "-enc",
                "-encodedcommand",
            ].contains(optionName) {
                let valueIndex = token.contains("=") ? index : index + 1
                return valueIndex < command.count ? (index, valueIndex) : nil
            }
            if optionName == "--" {
                return nil
            }
            if self.powerShellOptionConsumesNextArg(token) {
                index += 1
            }
            index += 1
        }
        return nil
    }

    private static func powerShellOptionName(_ token: String) -> String {
        token.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .split(separator: "=", maxSplits: 1)
            .first
            .map(String.init) ?? ""
    }

    private static func powerShellOptionConsumesNextArg(_ token: String) -> Bool {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        return [
            "-config",
            "-configurationfile",
            "-configurationname",
            "-custompipename",
            "-ea",
            "-en",
            "-enc",
            "-encodedarguments",
            "-encodedcommand",
            "-ex",
            "-ep",
            "-executionpolicy",
            "-if",
            "-inp",
            "-inputformat",
            "-o",
            "-of",
            "-outputformat",
            "-pscf",
            "-psconsolefile",
            "-settings",
            "-settingsfile",
            "-v",
            "-version",
            "-w",
            "-wd",
            "-wo",
            "-windowstyle",
            "-workingdirectory",
        ].contains(self.powerShellOptionName(trimmed)) && !trimmed.contains("=")
    }

    private static func isPowerShellFileExecutionOption(_ token: String) -> Bool {
        let optionName = self.powerShellOptionName(token)
        guard optionName.hasPrefix("-") || optionName.hasPrefix("/") else {
            return false
        }
        let switchName: Substring
        if optionName.hasPrefix("--") {
            switchName = optionName.dropFirst(2)
        } else {
            switchName = optionName.dropFirst()
        }
        return !switchName.isEmpty && "file".hasPrefix(String(switchName))
    }

    private static func isKnownPowerShellSlashOption(_ token: String) -> Bool {
        self.isPowerShellDisableProfileOption(token) ||
            self.isPowerShellLoginOption(token) ||
            self.isPowerShellFileExecutionOption(token)
    }

    private static func isPowerShellDisableProfileOption(_ token: String) -> Bool {
        ["-noprofile", "-nop", "/noprofile", "/nop"].contains(self.powerShellOptionName(token))
    }

    private static func isPowerShellLoginOption(_ token: String) -> Bool {
        ["-login", "-l", "/login", "/l"].contains(self.powerShellOptionName(token))
    }

    private static func optionName(_ token: String) -> String {
        token.split(separator: "=", maxSplits: 1).first.map(String.init) ?? token
    }

    private static func readPosixShortOptionScan(_ token: String) -> (inline: Bool, startup: Bool, consumesNextArg: Bool) {
        guard (token.hasPrefix("-") || token.hasPrefix("+")),
              !token.hasPrefix("--"),
              !token.hasPrefix("++"),
              token != "-",
              token != "+"
        else {
            return (false, false, false)
        }
        var inline = false
        var consumesNextArg = false
        for flag in token.dropFirst() {
            if token.hasPrefix("-"), flag == "c" {
                inline = true
                continue
            }
            if token.hasPrefix("-"), flag == "i" || flag == "l" {
                return (false, true, false)
            }
            if flag == "o" || flag == "O" {
                consumesNextArg = true
            }
        }
        return (inline, false, consumesNextArg)
    }

    private static func readFishShortCommandOption(_ token: String) -> (
        inline: Bool,
        startup: Bool,
        noConfig: Bool,
        consumesNextArg: Bool)
    {
        guard token.hasPrefix("-"), !token.hasPrefix("--"), token != "-" else {
            return (false, false, false, false)
        }
        var noConfig = false
        let flags = Array(token.dropFirst())
        for (index, flag) in flags.enumerated() {
            if flag == "N" {
                noConfig = true
                continue
            }
            if flag == "c" {
                return (true, false, noConfig, false)
            }
            if flag == "C" {
                return (false, true, noConfig, false)
            }
            if Set<Character>(["c", "C", "p", "d", "f", "D", "o"]).contains(flag) {
                return (false, false, noConfig, index == flags.count - 1)
            }
        }
        return (false, false, noConfig, false)
    }

    private static func updateZshRcsState(
        command: [String],
        index: Int,
        rcsEnabled: Bool) -> (rcsEnabled: Bool, consumedNextArg: Bool)
    {
        let token = command[index].trimmingCharacters(in: .whitespacesAndNewlines)
        let optionName = self.optionName(token).lowercased()
        let tokenLower = token.lowercased()
        if optionName == "--no-rcs" {
            return (false, false)
        }
        if optionName == "--rcs" || tokenLower == "-o=rcs" || optionName == "-orcs" {
            return (true, false)
        }
        if tokenLower == "+o=rcs" || optionName == "+orcs" ||
            tokenLower == "-o=norcs" || optionName == "-onorcs"
        {
            return (false, false)
        }
        if tokenLower == "+o=norcs" || optionName == "+onorcs" {
            return (true, false)
        }
        if optionName == "-o" || optionName == "+o" {
            let optionValue = index + 1 < command.count
                ? command[index + 1].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                : ""
            if optionValue == "rcs" {
                return (optionName == "-o", true)
            }
            if optionValue == "norcs" {
                return (optionName == "+o", true)
            }
            return (rcsEnabled, true)
        }
        let flags = token.dropFirst()
        if token.hasPrefix("-"), flags.contains("f") {
            return (false, false)
        }
        if token.hasPrefix("+"), flags.contains("f") {
            return (true, false)
        }
        return (rcsEnabled, false)
    }

    private static func isDirectShellPositionalCarrierInvocation(_ command: String) -> Bool {
        let pattern = #"^(?:exec[^\S\r\n]+(?:--[^\S\r\n]+)?)?(?:\$(?:0|\{0\})|"\$(?:0|\{0\})")(?:[^\S\r\n]+(?:\$(?:[@*]|[1-9]|\{[@*1-9]\})|"\$(?:[@*]|[1-9]|\{[@*1-9]\})"))*$"#
        return command.trimmingCharacters(in: .whitespacesAndNewlines)
            .range(of: pattern, options: .regularExpression) != nil
    }

    private static func unwrapShellMultiplexerInvocation(_ argv: [String]) -> [String]? {
        guard let token0 = argv.first?.trimmingCharacters(in: .whitespacesAndNewlines), !token0.isEmpty else {
            return nil
        }
        let wrapper = ExecCommandToken.basenameLower(token0)
        guard wrapper == "busybox" || wrapper == "toybox" else {
            return nil
        }

        var appletIndex = 1
        if appletIndex < argv.count, argv[appletIndex].trimmingCharacters(in: .whitespacesAndNewlines) == "--" {
            appletIndex += 1
        }
        guard appletIndex < argv.count else {
            return nil
        }
        let applet = argv[appletIndex].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !applet.isEmpty else {
            return nil
        }

        let normalizedApplet = ExecCommandToken.basenameLower(applet)
        let shellWrappers = Set([
            "ash",
            "bash",
            "dash",
            "fish",
            "ksh",
            "powershell",
            "pwsh",
            "sh",
            "zsh",
        ])
        guard shellWrappers.contains(normalizedApplet) else {
            return nil
        }
        return Array(argv[appletIndex...])
    }

    private static func parseFirstToken(_ command: String) -> String? {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard let first = trimmed.first else { return nil }
        if first == "\"" || first == "'" {
            let rest = trimmed.dropFirst()
            if let end = rest.firstIndex(of: first) {
                return String(rest[..<end])
            }
            return String(rest)
        }
        return trimmed.split(whereSeparator: { $0.isWhitespace }).first.map(String.init)
    }

    private static func tokenizeShellWords(_ command: String) -> [String] {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }

        var tokens: [String] = []
        var current = ""
        var inSingle = false
        var inDouble = false
        var escaped = false

        func appendCurrent() {
            guard !current.isEmpty else { return }
            tokens.append(current)
            current.removeAll(keepingCapacity: true)
        }

        for ch in trimmed {
            if escaped {
                current.append(ch)
                escaped = false
                continue
            }

            if ch == "\\", !inSingle {
                escaped = true
                continue
            }

            if ch == "'", !inDouble {
                inSingle.toggle()
                continue
            }

            if ch == "\"", !inSingle {
                inDouble.toggle()
                continue
            }

            if ch.isWhitespace, !inSingle, !inDouble {
                appendCurrent()
                continue
            }

            current.append(ch)
        }

        if escaped {
            current.append("\\")
        }
        appendCurrent()
        return tokens
    }

    private enum ShellTokenContext {
        case unquoted
        case doubleQuoted
    }

    private struct ShellFailClosedRule {
        let token: Character
        let next: Character?
    }

    private static let shellFailClosedRules: [ShellTokenContext: [ShellFailClosedRule]] = [
        .unquoted: [
            ShellFailClosedRule(token: "`", next: nil),
            ShellFailClosedRule(token: "$", next: "("),
            ShellFailClosedRule(token: "<", next: "("),
            ShellFailClosedRule(token: ">", next: "("),
        ],
        .doubleQuoted: [
            ShellFailClosedRule(token: "`", next: nil),
            ShellFailClosedRule(token: "$", next: "("),
        ],
    ]

    private static func splitShellCommandChain(_ command: String) -> [String]? {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        var segments: [String] = []
        var current = ""
        var inSingle = false
        var inDouble = false
        var escaped = false
        let chars = Array(trimmed)
        var idx = 0

        func appendCurrent() -> Bool {
            let segment = current.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !segment.isEmpty else { return false }
            segments.append(segment)
            current.removeAll(keepingCapacity: true)
            return true
        }

        while idx < chars.count {
            let ch = chars[idx]
            let next: Character? = idx + 1 < chars.count ? chars[idx + 1] : nil
            let lookahead = self.nextShellSignificantCharacter(chars: chars, after: idx, inSingle: inSingle)

            if escaped {
                if ch == "\n" {
                    escaped = false
                    idx += 1
                    continue
                }
                current.append(ch)
                escaped = false
                idx += 1
                continue
            }

            if ch == "\\", !inSingle {
                if next == "\n" {
                    idx += 2
                    continue
                }
                current.append(ch)
                escaped = true
                idx += 1
                continue
            }

            if ch == "'", !inDouble {
                inSingle.toggle()
                current.append(ch)
                idx += 1
                continue
            }

            if ch == "\"", !inSingle {
                inDouble.toggle()
                current.append(ch)
                idx += 1
                continue
            }

            if !inSingle, self.shouldFailClosedForShell(ch: ch, next: lookahead, inDouble: inDouble) {
                // Fail closed on command/process substitution in allowlist mode,
                // including command substitution inside double-quoted shell strings.
                return nil
            }

            if !inSingle, !inDouble {
                let prev: Character? = idx > 0 ? chars[idx - 1] : nil
                if let delimiterStep = self.chainDelimiterStep(ch: ch, prev: prev, next: next) {
                    guard appendCurrent() else { return nil }
                    idx += delimiterStep
                    continue
                }
            }

            current.append(ch)
            idx += 1
        }

        if escaped || inSingle || inDouble { return nil }
        guard appendCurrent() else { return nil }
        return segments
    }

    private static func nextShellSignificantCharacter(
        chars: [Character],
        after idx: Int,
        inSingle: Bool) -> Character?
    {
        guard !inSingle else {
            return idx + 1 < chars.count ? chars[idx + 1] : nil
        }
        var cursor = idx + 1
        while cursor < chars.count {
            if chars[cursor] == "\\", cursor + 1 < chars.count, chars[cursor + 1] == "\n" {
                cursor += 2
                continue
            }
            return chars[cursor]
        }
        return nil
    }

    private static func shouldFailClosedForShell(ch: Character, next: Character?, inDouble: Bool) -> Bool {
        let context: ShellTokenContext = inDouble ? .doubleQuoted : .unquoted
        guard let rules = self.shellFailClosedRules[context] else {
            return false
        }
        for rule in rules {
            if ch == rule.token, rule.next == nil || next == rule.next {
                return true
            }
        }
        return false
    }

    private static func chainDelimiterStep(ch: Character, prev: Character?, next: Character?) -> Int? {
        if ch == ";" || ch == "\n" {
            return 1
        }
        if ch == "&" {
            if next == "&" {
                return 2
            }
            // Keep fd redirections like 2>&1 or &>file intact.
            let prevIsRedirect = prev == ">"
            let nextIsRedirect = next == ">"
            return (!prevIsRedirect && !nextIsRedirect) ? 1 : nil
        }
        if ch == "|" {
            if next == "|" || next == "&" {
                return 2
            }
            return 1
        }
        return nil
    }

    private static func searchPaths(from env: [String: String]?) -> [String] {
        let raw = env?["PATH"]
        if let raw, !raw.isEmpty {
            return raw.split(separator: ":").map(String.init)
        }
        return CommandResolver.preferredPaths()
    }
}

enum ExecCommandFormatter {
    static func displayString(for argv: [String]) -> String {
        argv.map { arg in
            let trimmed = arg.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return "\"\"" }
            let needsQuotes = trimmed.contains { $0.isWhitespace || $0 == "\"" }
            if !needsQuotes { return trimmed }
            let escaped = trimmed.replacingOccurrences(of: "\"", with: "\\\"")
            return "\"\(escaped)\""
        }.joined(separator: " ")
    }

    static func displayString(for argv: [String], rawCommand: String?) -> String {
        let trimmed = rawCommand?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !trimmed.isEmpty { return trimmed }
        return self.displayString(for: argv)
    }
}
