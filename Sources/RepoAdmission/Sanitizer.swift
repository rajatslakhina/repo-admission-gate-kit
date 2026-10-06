/// One change the sanitizer will make.
public enum SanitizationAction: Hashable, Sendable {
    /// Remove `lines` from a config file. When `keepColumns` is set the key
    /// shares its first line with a section header (`[core] fsmonitor = x`):
    /// that line is cut at the key instead of deleted, so the header — and
    /// every key after it — keeps its section.
    case removeConfigLines(path: String, lines: ClosedRange<Int>, key: String, keepColumns: Int?)
    case deleteFile(path: String, reason: String)

    public var path: String {
        switch self {
        case .removeConfigLines(let path, _, _, _), .deleteFile(let path, _): path
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
/// That constraint is the design. Sanitizing edits only git metadata — `.git/`,
/// or the in-tree directory a `.git` file points at — local git
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
        // Re-read the repository's git metadata layout and parsed config so
        // the plan knows which hooks live in a git dir and where a key starts.
        let context = try? ScanContext(source: repo, limits: .default)
        let gitDirs = context?.gitDirs ?? []
        let configEntries = context?.gitConfig ?? []
        for finding in assessment.findings where finding.disposition != .allow {
            let vector = finding.vector
            switch vector.vectorClass {
            case .gitConfigCommand, .gitConfigInclude, .gitHooksPathRedirect:
                if let lines = vector.lines,
                   let entry = configEntries.first(where: { $0.source == vector.path && $0.lines == lines }) {
                    actions.append(.removeConfigLines(path: vector.path, lines: lines, key: vector.subject,
                                                      keepColumns: entry.keyColumn))
                    if vector.vectorClass == .gitHooksPathRedirect { removedHooksPath = true }
                } else {
                    unsanitizable.append(finding)
                }
            case .gitHook where gitDirs.contains(where: { PathText.directory(vector.path) == "\($0)/hooks" }):
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
            case .gitHook: removedHooksPath && !gitDirs.contains { finding.vector.path.hasPrefix("\($0)/") }
            case .gitAttributeDriverDefined:
                // subject is "filter=lfsx"; the definition's key is "filter.lfsx.<name>".
                actions.contains { action in
                    guard case .removeConfigLines(_, _, let key, _) = action else { return false }
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
        var linesToCut: [String: [Int: Int]] = [:]  // path → line → keep this many characters
        for action in actions {
            if case .removeConfigLines(let path, let lines, _, let keep) = action {
                var drop = Set(lines)
                if let keep {
                    drop.remove(lines.lowerBound)
                    linesToCut[path, default: [:]][lines.lowerBound] = keep
                }
                linesToDrop[path, default: []].formUnion(drop)
            }
        }
        for path in Set(linesToDrop.keys).union(linesToCut.keys).sorted() {
            let drop = linesToDrop[path] ?? []
            let cut = linesToCut[path] ?? [:]
            let bytes = try repo.read(path, limit: Int.max)
            // Split on the LF byte, exactly as the parser numbers lines (a CRLF
            // file keeps its "\r" in each kept line), and cut by Unicode scalars,
            // which is how `GitConfigEntry.keyColumn` is counted.
            let lines = bytes.split(separator: 0x0A, omittingEmptySubsequences: false)
            var kept: [String] = []
            for (offset, lineBytes) in lines.enumerated() {
                let number = offset + 1
                if drop.contains(number) { continue }
                let line = String(decoding: lineBytes, as: UTF8.self)
                if let keep = cut[number] {
                    let bom = (offset == 0 && line.unicodeScalars.first == "\u{FEFF}") ? 1 : 0
                    let prefix = String(String.UnicodeScalarView(line.unicodeScalars.prefix(max(0, keep) + bom)))
                    kept.append(prefix.trimmingSpaces() + (line.hasSuffix("\r") ? "\r" : ""))
                } else {
                    kept.append(line)
                }
            }
            try repo.write(Array(kept.joined(separator: "\n").utf8), to: path)
        }
        for action in actions {
            if case .deleteFile(let path, _) = action { try repo.remove(path) }
        }
    }
}
