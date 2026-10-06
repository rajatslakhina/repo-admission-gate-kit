import Foundation

/// Adapter between `AdmissionGate` and a Claude Code `PreToolUse` hook.
///
/// The library ships no executable (an executable target in a library package
/// is a build-time artifact this gate would itself have to admit). The consumer
/// wraps this in ~10 lines of their own CLI — see the README — and registers it:
///
/// ```json
/// { "hooks": { "PreToolUse": [ { "matcher": "Bash",
///     "hooks": [ { "type": "command", "command": "repo-admission-hook" } ] } ] } }
/// ```
///
/// One rule shapes the output: **the gate can only subtract permission, never
/// add it.** For an allowed command it prints nothing, so Claude Code's own
/// permission rules still apply. Emitting `"permissionDecision": "allow"` would
/// skip them — turning a security gate into a way around the user's settings.
public enum ClaudeCodeHook {
    public struct Input: Decodable, Sendable {
        public let hookEventName: String?
        public let toolName: String
        public let toolInput: ToolInput
        public let cwd: String

        public struct ToolInput: Decodable, Sendable {
            public let command: String?
        }

        enum CodingKeys: String, CodingKey {
            case hookEventName = "hook_event_name"
            case toolName = "tool_name"
            case toolInput = "tool_input"
            case cwd
        }
    }

    struct Output: Encodable {
        struct Specific: Encodable {
            let hookEventName = "PreToolUse"
            let permissionDecision: String
            let permissionDecisionReason: String
        }
        let hookSpecificOutput: Specific
    }

    /// Returns the bytes to print on stdout, or nil to print nothing.
    public static func respond(to stdin: Data, gate: AdmissionGate,
                               repoAt: @escaping @Sendable (URL) throws -> any RepoFileSource = { DirectoryRepo(root: $0) }) async -> Data? {
        let input: Input
        do {
            input = try JSONDecoder().decode(Input.self, from: stdin)
        } catch {
            return render(.deny, "repo-admission could not parse the hook input (\(error)); failing closed.")
        }
        guard input.toolName == "Bash", let command = input.toolInput.command else { return nil }
        let base = URL(fileURLWithPath: input.cwd, isDirectory: true)
        // Git walks UP from the working directory to find its repository, so
        // the gate must too: `cd Sources && git status` runs the root's
        // fsmonitor, and a session started in a subdirectory is still inside
        // the repository. Scanning only the subdirectory would see no `.git`.
        let resolve: @Sendable (String) -> URL = { directory in
            let start = directory.hasPrefix("/") ? URL(fileURLWithPath: directory) : base.appendingPathComponent(directory)
            return repositoryRoot(containing: start.standardizedFileURL)
        }
        let decision = await gate.decide(command, repoKey: { resolve($0).path }, repoAt: { try repoAt(resolve($0)) })
        switch decision.verdict {
        case .allow: return nil
        case .ask, .deny: return render(decision.verdict, decision.reason)
        }
    }

    /// The nearest directory at or above `directory` that contains a `.git`
    /// entry (directory or file), or `directory` itself if there is none — in
    /// which case git has no repository to run hooks from, and the scan of
    /// `directory` still covers its manifests and projects.
    public static func repositoryRoot(containing directory: URL) -> URL {
        var current = directory.standardizedFileURL
        // Bounded: path depth is finite, and `deletingLastPathComponent` of "/" is "/".
        for _ in 0..<256 {
            if FileManager.default.fileExists(atPath: current.appendingPathComponent(".git").path) { return current }
            let parent = current.deletingLastPathComponent().standardizedFileURL
            if parent.path == current.path { break }
            current = parent
        }
        return directory.standardizedFileURL
    }

    static func render(_ verdict: Verdict, _ reason: String) -> Data? {
        let output = Output(hookSpecificOutput: .init(permissionDecision: verdict.rawValue, permissionDecisionReason: reason))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try? encoder.encode(output)
    }
}
