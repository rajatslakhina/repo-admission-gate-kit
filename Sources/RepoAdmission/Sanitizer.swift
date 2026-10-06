/// One change the sanitizer will make.
public enum SanitizationAction: Hashable, Sendable {
    case removeConfigLines(path: String, lines: ClosedRange<Int>, key: String)
    case deleteFile(path: String, reason: String)

    public var path: String {
        switch self {
        case .removeConfigLines(let path, _, _), .deleteFile(let path, _): path
        }
    }
}

public enum SanitizationError: Error, Equatable, Sendable {
    /// A file changed between planning and applying. Applying anyway would
    /// delete lines by number from a file we never looked at.
    case stale(path: String)
    case missing(path: String)
}

/// A plan to neutralise every vector that can be neutralised without touching
/// a single tracked file.
///
/// That constraint is the design. Sanitizing edits only `.git/` — local git
/// metadata no commit, diff or pull request will ever show — so the agent's
/// working tree stays byte-identical and its eventual diff contains only its
/// own work. The cost: tracked vectors (a script phase, a plugin, a poisoned
/// `.gitmodules`) cannot be sanitized; they need approval or a human edit.
public struct SanitizationPlan: Sendable, Equatable {
    public let actions: [SanitizationAction]
    /// Vectors the plan cannot neutralise (and that are not `.allow`).
    public let unsanitizable: [Finding]
    /// Digest of each file the plan touches, as it was when planned.
    public let baseline: [String: Digest]

    public var isEmpty: Bool { actions.isEmpty }

    static let sanitizableClasses: Set<VectorClass> = [.gitConfigCommand, .gitConfigInclude, .gitHooksPathRedirect, .gitHook]

    public init(assessment: Assessment, repo: some RepoFileSource) {
        var actions: [SanitizationAction] = []
        var unsanitizable: [Finding] = []
        var removedHooksPath = false
        for finding in assessment.findings where finding.disposition != .allow {
            let vector = finding.vector
            switch vector.vectorClass {
            case .gitConfigCommand, .gitConfigInclude, .gitHooksPathRedirect:
                if vector.path == ".git/config", let lines = vector.lines {
                    actions.append(.removeConfigLines(path: vector.path, lines: lines, key: vector.subject))
                    if vector.vectorClass == .gitHooksPathRedirect { removedHooksPath = true }
                } else {
                    unsanitizable.append(finding)
                }
            case .gitHook where vector.path.hasPrefix(".git/hooks/"):
                actions.append(.deleteFile(path: vector.path, reason: "active \(vector.subject) hook"))
            default:
                unsanitizable.append(finding)
            }
        }
        // Hooks in a tracked directory are neutralised by removing the
        // core.hooksPath that pointed at them, and attribute drivers by removing
        // the config that defined them — not by touching tracked files.
        let neutralisedIndirectly: (Finding) -> Bool = { finding in
            switch finding.vector.vectorClass {
            case .gitHook: removedHooksPath && !finding.vector.path.hasPrefix(".git/")
            case .gitAttributeDriverDefined:
                // subject is "filter=lfsx"; the definition's key is "filter.lfsx.<name>".
                actions.contains { action in
                    guard case .removeConfigLines(_, _, let key) = action else { return false }
                    return key.hasPrefix(finding.vector.subject.replacingFirst("=", with: ".") + ".")
                }
            default: false
            }
        }
        self.actions = actions
        self.unsanitizable = unsanitizable.filter { !neutralisedIndirectly($0) }
        var baseline: [String: Digest] = [:]
        for path in Set(actions.map(\.path)) {
            if let bytes = try? repo.read(path, limit: Int.max) { baseline[path] = .of(bytes: bytes) }
        }
        self.baseline = baseline
    }

    /// Apply to a writable repository. All-or-nothing on staleness: every file
    /// is checked against its baseline before anything is written.
    public func apply<R: WritableRepo>(to repo: inout R) throws {
        for (path, expected) in baseline {
            guard let bytes = try? repo.read(path, limit: Int.max) else { throw SanitizationError.missing(path: path) }
            guard Digest.of(bytes: bytes) == expected else { throw SanitizationError.stale(path: path) }
        }
        var linesToDrop: [String: Set<Int>] = [:]
        for action in actions {
            if case .removeConfigLines(let path, let lines, _) = action {
                linesToDrop[path, default: []].formUnion(lines)
            }
        }
        for (path, drop) in linesToDrop.sorted(by: { $0.key < $1.key }) {
            let bytes = try repo.read(path, limit: Int.max)
            let lines = String(decoding: bytes, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
            let kept = lines.enumerated().filter { !drop.contains($0.offset + 1) }.map(\.element)
            try repo.write(Array(kept.joined(separator: "\n").utf8), to: path)
        }
        for action in actions {
            if case .deleteFile(let path, _) = action { try repo.remove(path) }
        }
    }
}
