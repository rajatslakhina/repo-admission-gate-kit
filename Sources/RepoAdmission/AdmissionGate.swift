import Foundation

/// A human's approval of one repository's executable surface.
public struct ApprovalRecord: Codable, Sendable, Equatable {
    public let repo: String
    /// The `Assessment.approvalSurface` the human was shown.
    public let surface: Digest
    public let approver: String
    public let timestampMilliseconds: Int64
}

/// Where approvals live between hook invocations (each Claude Code hook call
/// is a fresh process).
public protocol AdmissionStore: Sendable {
    func approval(for repo: String) throws -> ApprovalRecord?
    func save(_ record: ApprovalRecord) throws
    func removeApproval(for repo: String) throws
}

public final class InMemoryAdmissionStore: AdmissionStore, @unchecked Sendable {
    // @unchecked: every access to `records` goes through `lock`.
    private let lock = NSLock()
    private var records: [String: ApprovalRecord] = [:]

    public init() {}

    public func approval(for repo: String) -> ApprovalRecord? {
        lock.lock(); defer { lock.unlock() }
        return records[repo]
    }

    public func save(_ record: ApprovalRecord) {
        lock.lock(); defer { lock.unlock() }
        records[record.repo] = record
    }

    public func removeApproval(for repo: String) {
        lock.lock(); defer { lock.unlock() }
        records[repo] = nil
    }
}

/// Approvals as one JSON file, written atomically. Keep it outside every
/// repository it describes — a repo must not be able to ship its own approval.
public struct JSONFileAdmissionStore: AdmissionStore {
    public let url: URL

    public init(url: URL) { self.url = url }

    private func load() throws -> [String: ApprovalRecord] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
        return try JSONDecoder().decode([String: ApprovalRecord].self, from: Data(contentsOf: url))
    }

    public func approval(for repo: String) throws -> ApprovalRecord? { try load()[repo] }

    public func save(_ record: ApprovalRecord) throws {
        var all = try load()
        all[record.repo] = record
        try write(all)
    }

    public func removeApproval(for repo: String) throws {
        var all = try load()
        all[repo] = nil
        try write(all)
    }

    private func write(_ all: [String: ApprovalRecord]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(all).write(to: url, options: .atomic)
    }
}

/// What to do when a fired vector needs approval and none matches.
public enum UnapprovedMode: Sendable, Equatable {
    /// Refuse, and say exactly what to approve. The default: an "ask" click in
    /// a permission prompt is bound to nothing, leaves no provenance, and is
    /// exactly what a tired human approves without reading.
    case deny
    /// Defer to Claude Code's permission prompt.
    case ask
}

public struct GateDecision: Sendable, Equatable {
    public let command: String
    public let verdict: Verdict
    public let reason: String
    /// Non-allowed findings that this command would fire.
    public let fired: [Finding]
    public let triggers: Set<Trigger>
}

public enum AdmissionError: Error, Equatable, Sendable {
    /// The surface the human approved is no longer the repository's surface.
    case staleApproval(approved: Digest, current: Digest)
}

/// The gate: scan → assess → decide, with approvals bound to content.
///
/// An actor so one process can serve concurrent hook requests, and so the
/// approval store and provenance log are mutated in one place. No method
/// contains an `await`: scanning, assessment and the store are synchronous,
/// so a decision is computed atomically with respect to approvals and no other
/// call can interleave mid-decision (no actor-reentrancy window).
///
/// It rescans on *every* gated call instead of caching an assessment. A cache
/// is precisely the time-of-check/time-of-use window this exists to close:
/// approve, then `git pull` brings a new script phase, then `xcodebuild`.
public actor AdmissionGate {
    public let policy: AdmissionPolicy
    public let scanner: RepoScanner
    public let mode: UnapprovedMode
    private let store: any AdmissionStore
    private let clock: @Sendable () -> Date
    private let surfaceOf: @Sendable (Assessment) -> Digest
    public private(set) var log: ProvenanceLog

    public init(policy: AdmissionPolicy = .strict,
                scanner: RepoScanner = .standard,
                store: any AdmissionStore = InMemoryAdmissionStore(),
                mode: UnapprovedMode = .deny,
                logCapacity: Int = 1_000,
                log: ProvenanceLog? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        // A hook runs as a fresh process per tool call; passing the previously
        // persisted log in keeps one continuous chain across invocations.
        self.init(policy: policy, scanner: scanner, store: store, mode: mode, logCapacity: logCapacity,
                  clock: clock, surfaceOf: { $0.approvalSurface }, log: log)
    }

    /// Internal seam so tests can inject a deliberately broken surface function
    /// and prove the "edit after approval re-quarantines" test discriminates.
    init(policy: AdmissionPolicy, scanner: RepoScanner, store: any AdmissionStore, mode: UnapprovedMode,
         logCapacity: Int, clock: @escaping @Sendable () -> Date, surfaceOf: @escaping @Sendable (Assessment) -> Digest,
         log: ProvenanceLog? = nil) {
        self.policy = policy
        self.scanner = scanner
        self.store = store
        self.mode = mode
        self.clock = clock
        self.surfaceOf = surfaceOf
        self.log = log ?? ProvenanceLog(capacity: logCapacity)
    }

    /// Scan and assess, and record the assessment.
    public func assess(repo key: String, _ repo: some RepoFileSource) throws -> Assessment {
        let assessment = policy.evaluate(try scanner.scan(repo))
        log.append(.assessed(repo: key, inventory: assessment.inventory.digest, surface: surfaceOf(assessment),
                             blocking: assessment.blocking.count, pending: assessment.pendingApproval.count), at: clock())
        return assessment
    }

    /// The surface a human must approve right now.
    public func surface(of assessment: Assessment) -> Digest { surfaceOf(assessment) }

    /// Approve the repository's current surface. `expected` is the surface the
    /// human was shown; if the tree changed since, this throws instead of
    /// approving something nobody looked at.
    ///
    /// Approval covers only `.requireApproval` findings. Any `.deny` finding
    /// keeps blocking the operations that fire it whether or not an approval
    /// exists — so approving a repo with a poisoned `.gitmodules` admits
    /// `swift build` but never `git submodule update`.
    @discardableResult
    public func approve(repo key: String, _ repo: some RepoFileSource, expected: Digest, approver: String) throws -> ApprovalRecord {
        let assessment = policy.evaluate(try scanner.scan(repo))
        let current = surfaceOf(assessment)
        guard current == expected else { throw AdmissionError.staleApproval(approved: expected, current: current) }
        let record = ApprovalRecord(repo: key, surface: current, approver: approver,
                                    timestampMilliseconds: Saturating.milliseconds(clock().timeIntervalSince1970))
        try store.save(record)
        log.append(.approved(repo: key, surface: current, approver: approver), at: clock())
        return record
    }

    public func revoke(repo key: String) throws {
        try store.removeApproval(for: key)
        log.append(.revoked(repo: key), at: clock())
    }

    public func approval(for key: String) throws -> ApprovalRecord? { try store.approval(for: key) }

    /// Plan sanitization for the repository's current state.
    public func sanitizationPlan(_ repo: some RepoFileSource) throws -> SanitizationPlan {
        SanitizationPlan(assessment: policy.evaluate(try scanner.scan(repo)), repo: repo)
    }

    /// Apply a plan and record it.
    @discardableResult
    public func sanitize<R: WritableRepo>(repo key: String, _ repo: inout R) throws -> SanitizationPlan {
        let plan = SanitizationPlan(assessment: policy.evaluate(try scanner.scan(repo)), repo: repo)
        try plan.apply(to: &repo)
        log.append(.sanitized(repo: key, actions: plan.actions.count, remaining: plan.unsanitizable.count), at: clock())
        return plan
    }

    /// Decide a `Bash` tool call.
    ///
    /// - Parameters:
    ///   - command: the shell command line.
    ///   - repoKey: maps an invocation's directory to the key approvals are
    ///     stored under (normally its absolute path).
    ///   - repoAt: maps an invocation's directory to a source to scan. Throwing
    ///     here is a *deny*: a repository the gate cannot read is not admitted.
    public func decide(_ command: String,
                       repoKey: @Sendable (String) -> String = { $0 },
                       repoAt: @Sendable (String) throws -> any RepoFileSource) -> GateDecision {
        let classified = CommandClassifier.classify(command)
        let triggers = classified.triggers

        func finish(_ verdict: Verdict, _ reason: String, _ fired: [Finding] = []) -> GateDecision {
            if !triggers.isEmpty || verdict != .allow || !classified.concerns.isEmpty {
                log.append(.decided(command: command, verdict: verdict, reason: reason), at: clock())
            }
            return GateDecision(command: command, verdict: verdict, reason: reason, fired: fired, triggers: triggers)
        }

        let injections = classified.concerns.filter { if case .injection = $0 { true } else { false } }
        if !injections.isEmpty {
            return finish(.deny, "Command-level injection: " + injections.map(\.message).joined(separator: "; "))
        }

        var allFired: [Finding] = []
        var unapproved: [(key: String, fired: [Finding], surface: Digest)] = []
        for directory in Set(classified.invocations.filter { !$0.triggers.isEmpty }.map(\.directory)).sorted() {
            let dirTriggers = classified.invocations.filter { $0.directory == directory }
                .reduce(into: Set<Trigger>()) { $0.formUnion($1.triggers) }
            let key = repoKey(directory)
            let assessment: Assessment
            do {
                assessment = policy.evaluate(try scanner.scan(try repoAt(directory)))
            } catch {
                return finish(.deny, "Could not scan \(key) (\(error)); an unreadable repository is not admitted.")
            }
            let fired = assessment.findings.filter { $0.disposition != .allow && !$0.vector.firedBy.isDisjoint(with: dirTriggers) }
            allFired += fired
            let denied = fired.filter { $0.disposition == .deny }
            if !denied.isEmpty {
                return finish(.deny, "Blocked in \(key): " + Self.describe(denied)
                              + " — no approval clears a deny; sanitize the repository or change the policy.", fired)
            }
            guard !fired.isEmpty else { continue }
            let current = surfaceOf(assessment)
            let approval: ApprovalRecord?
            do { approval = try store.approval(for: key) } catch {
                return finish(.deny, "Approval store unreadable (\(error)); failing closed.", fired)
            }
            if let approval, approval.surface == current { continue }
            if let approval {
                log.append(.approvalVoided(repo: key, approved: approval.surface, current: current), at: clock())
            }
            unapproved.append((key, fired, current))
        }

        if let first = unapproved.first {
            let detail = unapproved.map { "\($0.key): " + Self.describe($0.fired) }.joined(separator: " | ")
            let stale = (try? store.approval(for: first.key)) != nil ? " The previous approval no longer matches: the executable surface changed." : ""
            let reason = "Needs approval — \(detail).\(stale) Approve surface \(first.surface.short) after reviewing it."
            return finish(mode == .deny ? .deny : .ask, reason, allFired)
        }

        if !classified.concerns.isEmpty {
            return finish(.ask, "Cannot see through this command: " + classified.concerns.map(\.message).joined(separator: "; "), allFired)
        }
        return finish(.allow, triggers.isEmpty ? "No repository code runs." : "Every vector this command fires is allowed or approved.", allFired)
    }

    static func describe(_ findings: [Finding], limit: Int = 5) -> String {
        let shown = findings.prefix(max(0, limit)).map { "\($0.vector.vectorClass.rawValue) `\($0.vector.subject)` in \($0.vector.path)" }
        let more = findings.count > limit ? " (+\(findings.count - limit) more)" : ""
        return shown.joined(separator: ", ") + more
    }
}
