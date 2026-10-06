/// Shared, read-once view of a repository for one scan.
///
/// A reference type on purpose: scanners record integrity problems (oversized,
/// symlinked or unparseable control files) here instead of silently skipping
/// them, and the composed scanner turns those into findings. It is created and
/// discarded inside a single synchronous `RepoScanner.scan` call and never
/// shared across threads.
public final class ScanContext {
    public let entries: [RepoEntry]
    public let limits: ScanLimits
    private let source: any RepoFileSource
    private var cache: [String: [UInt8]] = [:]
    private(set) var problems: [ExecutionVector] = []
    private var reported = Set<String>()

    init(source: any RepoFileSource, limits: ScanLimits) throws {
        self.source = source
        self.limits = limits
        self.entries = try source.entries()
    }

    /// Paths of regular files matching a predicate.
    public func files(where predicate: (String) -> Bool) -> [String] {
        entries.compactMap { entry in
            guard predicate(entry.path) else { return nil }
            if case .symlink(let target) = entry.kind {
                reportProblem(path: entry.path, detail: "control file is a symbolic link to \(target); not followed")
                return nil
            }
            return entry.path
        }
    }

    public func exists(_ path: String) -> Bool { entries.contains { $0.path == path } }

    /// File text, or nil — with the reason recorded as an integrity finding.
    public func text(_ path: String) -> String? {
        bytes(path).map { String(decoding: $0, as: UTF8.self) }
    }

    public func bytes(_ path: String) -> [UInt8]? {
        if let cached = cache[path] { return cached }
        do {
            let value = try source.read(path, limit: limits.maxFileBytes)
            cache[path] = value
            return value
        } catch RepoReadError.tooLarge(_, let size, let limit) {
            reportProblem(path: path, detail: "control file is \(size) bytes, over the \(limit)-byte scan limit")
        } catch {
            reportProblem(path: path, detail: "could not read control file: \(error)")
        }
        return nil
    }

    /// Record that a control file could not be inspected. The resulting finding
    /// is fired by every trigger: a file we could not read could contain anything.
    public func reportProblem(path: String, detail: String) {
        guard reported.insert(path).inserted else { return }
        problems.append(ExecutionVector(
            vectorClass: .unscannableControlFile, subject: path, path: path,
            payload: detail, firedBy: Set(Trigger.allCases)))
    }

    // Parsed `.git/config`, computed once and shared by the config, hooks and
    // attributes scanners (attributes are only dangerous if config defines the driver).
    public private(set) lazy var gitConfig: [GitConfigEntry] = {
        guard exists(".git/config"), let text = text(".git/config") else { return [] }
        return GitConfigParser.parse(text)
    }()
}

/// One family's scanner.
public protocol VectorScanner: Sendable {
    var name: String { get }
    func scan(_ context: ScanContext) -> [ExecutionVector]
}

/// Composes the per-family scanners into one inventory.
///
/// The scan is synchronous and pure with respect to its input snapshot, which
/// is what lets `AdmissionGate` (an actor) run it without a suspension point —
/// there is no `await` inside a decision, so no actor-reentrancy window in
/// which another call can change the state a decision is being made against.
public struct RepoScanner: Sendable {
    public let scanners: [any VectorScanner]
    public let limits: ScanLimits

    public init(scanners: [any VectorScanner], limits: ScanLimits = .default) {
        self.scanners = scanners
        self.limits = limits
    }

    public static let standard = RepoScanner(scanners: [
        GitConfigScanner(),
        GitHooksScanner(),
        GitAttributesScanner(),
        PackageManifestScanner(),
        XcodeProjectScanner(),
    ])

    public func scan(_ repo: some RepoFileSource) throws -> Inventory {
        let context = try ScanContext(source: repo, limits: limits)
        var vectors: [ExecutionVector] = []
        for scanner in scanners {
            vectors.append(contentsOf: scanner.scan(context))
        }
        vectors.append(contentsOf: context.problems)
        return Inventory(vectors: vectors, entriesScanned: context.entries.count)
    }
}

enum PathText {
    static func lastComponent(_ path: String) -> String {
        path.split(separator: "/", omittingEmptySubsequences: true).last.map(String.init) ?? path
    }

    static func directory(_ path: String) -> String {
        guard let slash = path.lastIndex(of: "/") else { return "" }
        return String(path[..<slash])
    }

    /// Lexically normalise a relative path. Returns nil if it climbs above
    /// the root ("../x") — the caller decides what escaping means.
    static func normalize(_ path: String) -> String? {
        var parts: [Substring] = []
        for part in path.split(separator: "/", omittingEmptySubsequences: true) {
            if part == "." { continue }
            if part == ".." {
                guard !parts.isEmpty else { return nil }
                parts.removeLast()
            } else {
                parts.append(part)
            }
        }
        return parts.joined(separator: "/")
    }

    static func join(_ base: String, _ relative: String) -> String {
        if relative.hasPrefix("/") { return relative }
        if base.isEmpty || base == "." { return relative }
        return "\(base)/\(relative)"
    }
}
