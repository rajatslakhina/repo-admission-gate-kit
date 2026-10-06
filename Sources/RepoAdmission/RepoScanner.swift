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
    private var bytesRead = 0
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
        bytes(path).map(Self.normalizedText)
    }

    /// Decode as UTF-8, drop a leading BOM and turn CRLF into LF.
    ///
    /// Every line-based scanner works on this, because Swift's Character
    /// treats "\r\n" as a single grapheme: without it a CRLF `.git/config`,
    /// `Package.swift` or `.xcconfig` reads as one long line (and a `//` comment
    /// on line 1 of a manifest swallows the whole file) — while git and SwiftPM
    /// read them line by line and run what is in them. LF-only input is
    /// unchanged, so line numbers still match the file on disk.
    static func normalizedText(_ bytes: [UInt8]) -> String {
        var view = String.UnicodeScalarView()
        var scalars = String(decoding: bytes, as: UTF8.self).unicodeScalars[...]
        if scalars.first == "\u{FEFF}" { scalars = scalars.dropFirst() }
        var pendingCR = false
        for scalar in scalars {
            if pendingCR, scalar != "\n" { view.append("\r") }
            pendingCR = scalar == "\r"
            if !pendingCR { view.append(scalar) }
        }
        if pendingCR { view.append("\r") }
        return String(view)
    }

    public func bytes(_ path: String) -> [UInt8]? {
        if let cached = cache[path] { return cached }
        do {
            let remaining = max(0, limits.maxTotalBytes - bytesRead)
            guard remaining > 0 else {
                reportProblem(path: path, detail: "scan byte budget (\(limits.maxTotalBytes) bytes in total) exhausted before this control file")
                return nil
            }
            let value = try source.read(path, limit: min(limits.maxFileBytes, remaining))
            bytesRead = Saturating.add(bytesRead, value.count)
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

    /// The git metadata directories inside the tree: `.git` when it is a
    /// directory, or the in-tree target of a `.git` *file* (`gitdir: meta`),
    /// plus the in-tree `commondir` either one names. A `.git` file is how
    /// worktrees and submodules point at their metadata — and how a received
    /// repository would hide its config from a scanner that only reads
    /// `.git/config`.
    public private(set) lazy var gitDirs: [String] = {
        var bases: [String] = []
        if entries.contains(where: { $0.path.hasPrefix(".git/") }) {
            bases.append(".git")
        } else if exists(".git"), let pointer = text(".git") {
            let target = Self.gitdirTarget(pointer)
            if !target.hasPrefix("/"), let normalized = PathText.normalize(target), !normalized.isEmpty {
                bases.append(normalized)
            }
        }
        var result = bases
        for base in bases {
            guard exists("\(base)/commondir"), let raw = text("\(base)/commondir") else { continue }
            let value = raw.trimmingSpaces().split(separator: "\n").first.map(String.init) ?? ""
            if !value.hasPrefix("/"), let normalized = PathText.normalize(PathText.join(base, value)),
               !normalized.isEmpty, !result.contains(normalized) {
                result.append(normalized)
            }
        }
        return result
    }()

    /// `commondir` files whose target leaves the tree: (git dir, target).
    var escapingCommonDirs: [(String, String)] {
        gitDirs.compactMap { base in
            guard exists("\(base)/commondir"), let raw = text("\(base)/commondir") else { return nil }
            let value = raw.trimmingSpaces().split(separator: "\n").first.map(String.init) ?? ""
            if value.hasPrefix("/") || PathText.normalize(PathText.join(base, value)) == nil { return (base, value) }
            return nil
        }
    }

    static func gitdirTarget(_ pointer: String) -> String {
        pointer.replacingFirst("gitdir:", with: "").trimmingSpaces()
            .split(separator: "\n").first.map { String($0).trimmingSpaces() } ?? ""
    }

    public func isInsideGitDir(_ path: String) -> Bool {
        gitDirs.contains { path.hasPrefix("\($0)/") }
    }

    // Every config file in every git dir, parsed once and shared by the config,
    // hooks and attributes scanners (attributes are only dangerous if config
    // defines the driver).
    public private(set) lazy var gitConfig: [GitConfigEntry] = {
        gitDirs.flatMap { base in
            ["config", "config.worktree"].flatMap { file -> [GitConfigEntry] in
                let path = "\(base)/\(file)"
                guard exists(path), let text = text(path) else { return [] }
                return GitConfigParser.parse(text, source: path)
            }
        }
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
