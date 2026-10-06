import XCTest
@testable import RepoAdmission

final class ProvenanceLogTests: XCTestCase {
    private func filled(_ count: Int, capacity: Int = 100) -> ProvenanceLog {
        var log = ProvenanceLog(capacity: capacity)
        for i in 0..<count {
            log.append(.decided(command: "cmd \(i)", verdict: .allow, reason: "r"), at: Date(timeIntervalSince1970: Double(i)))
        }
        return log
    }

    func testIntactChainVerifies() {
        XCTAssertEqual(filled(5).verify(), .intact(entries: 5))
        XCTAssertEqual(ProvenanceLog().verify(), .intact(entries: 0))
    }

    func testEditingOneEntryBreaksTheChainAtThatEntry() {
        var log = filled(5)
        guard let original = log.entries[safe: 2] else { return XCTFail() }
        log.entries[2] = ProvenanceEntry(sequence: original.sequence, timestampMilliseconds: original.timestampMilliseconds,
                                         event: .decided(command: "cmd 2", verdict: .deny, reason: "r"),
                                         previous: original.previous, hash: original.hash)
        XCTAssertEqual(log.verify(), .broken(atSequence: 2, reason: "entry content does not match its hash"))
    }

    func testDeletingAnEntryIsDetected() {
        var log = filled(5)
        log.entries.remove(at: 1)
        guard case .broken(let sequence, _) = log.verify() else { return XCTFail("deletion went unnoticed") }
        XCTAssertEqual(sequence, 2)
    }

    func testBoundedLogKeepsVerifyingAfterTruncation() {
        let log = filled(50, capacity: 10)
        XCTAssertEqual(log.entries.count, 10)
        XCTAssertEqual(log.droppedCount, 40)
        XCTAssertEqual(log.entries.first?.sequence, 40)
        XCTAssertEqual(log.verify(), .intact(entries: 10))
        XCTAssertEqual(ProvenanceLog(capacity: 0).capacity, 1)
    }

    func testCodableRoundTripStillVerifies() throws {
        let log = filled(3)
        let decoded = try JSONDecoder().decode(ProvenanceLog.self, from: JSONEncoder().encode(log))
        XCTAssertEqual(decoded.verify(), .intact(entries: 3))
        XCTAssertEqual(decoded.head, log.head)
    }
}

final class SanitizerTests: XCTestCase {
    func testSanitizedRepoHasNoSanitizableVectorsLeft() throws {
        var repo = RedTeamFixture.repo
        let plan = SanitizationPlan(assessment: AdmissionPolicy.strict.evaluate(try RepoScanner.standard.scan(repo)), repo: repo)
        try plan.apply(to: &repo)
        let after = AdmissionPolicy.strict.evaluate(try RepoScanner.standard.scan(repo))
        let leftovers = after.findings.filter {
            $0.disposition != .allow && SanitizationPlan.sanitizableClasses.contains($0.vector.vectorClass)
        }
        XCTAssertEqual(leftovers, [])
        XCTAssertNil(repo.files[".git/hooks/post-checkout"])
        XCTAssertNotNil(repo.files[".git/hooks/pre-commit.sample"], "decoys are left alone")
        let config = repo.text(".git/config") ?? ""
        XCTAssertTrue(config.contains("lg = log --oneline"), "harmless config survives")
        XCTAssertTrue(config.contains("[remote \"origin\"]"))
        XCTAssertFalse(config.contains("&& cat"), "a continuation line goes with its key")
        // Attribute drivers are neutralised by removing their config, not by
        // editing the tracked .gitattributes.
        XCTAssertTrue(after.findings.filter { $0.vector.family == .gitAttributes && $0.vector.vectorClass != .gitSubmoduleInjection }
            .allSatisfy { $0.vector.vectorClass == .gitAttributeDriverLatent })
    }

    func testStalePlanIsRefusedWithoutWritingAnything() throws {
        var repo = RedTeamFixture.repo
        let plan = SanitizationPlan(assessment: AdmissionPolicy.strict.evaluate(try RepoScanner.standard.scan(repo)), repo: repo)
        repo.write((repo.text(".git/config") ?? "") + "\n[core]\n\teditor = vim\n", to: ".git/config")
        let before = repo
        XCTAssertThrowsError(try plan.apply(to: &repo)) { error in
            XCTAssertEqual(error as? SanitizationError, .stale(path: ".git/config"))
        }
        XCTAssertEqual(repo, before)
    }
}

final class ClaudeCodeHookTests: XCTestCase {
    private func input(_ command: String, tool: String = "Bash", cwd: String = "/repo") -> Data {
        let payload: [String: Any] = ["hook_event_name": "PreToolUse", "tool_name": tool,
                                      "tool_input": ["command": command], "cwd": cwd, "session_id": "s"]
        return (try? JSONSerialization.data(withJSONObject: payload)) ?? Data()
    }

    private func decode(_ data: Data?) -> [String: String]? {
        guard let data, let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return object["hookSpecificOutput"] as? [String: String]
    }

    func testDenyIsRenderedInClaudeCodesSchema() async {
        let gate = AdmissionGate()
        let fixture = RedTeamFixture.repo
        let out = decode(await ClaudeCodeHook.respond(to: input("git status"), gate: gate, repoAt: { _ in fixture }))
        XCTAssertEqual(out?["hookEventName"], "PreToolUse")
        XCTAssertEqual(out?["permissionDecision"], "deny")
        XCTAssertTrue(out?["permissionDecisionReason"]?.contains("core.fsmonitor") ?? false)
    }

    /// The gate subtracts permission and never adds it: an allowed command
    /// produces no output, so Claude Code's own permission rules still run.
    func testAllowPrintsNothingAndOtherToolsAreIgnored() async {
        let gate = AdmissionGate()
        let fixture = RedTeamFixture.repo
        let allowed = await ClaudeCodeHook.respond(to: input("ls"), gate: gate, repoAt: { _ in fixture })
        XCTAssertNil(allowed)
        let edit = await ClaudeCodeHook.respond(to: input("x", tool: "Edit"), gate: gate, repoAt: { _ in fixture })
        XCTAssertNil(edit)
    }

    func testMalformedInputFailsClosed() async {
        let out = decode(await ClaudeCodeHook.respond(to: Data("not json".utf8), gate: AdmissionGate()))
        XCTAssertEqual(out?["permissionDecision"], "deny")
    }

    func testInvocationDirectoriesResolveAgainstTheHookCwd() async {
        let gate = AdmissionGate()
        let seen = Locked<[String]>([])
        _ = await ClaudeCodeHook.respond(to: input("cd Packages/Core && swift build; git -C /abs status", cwd: "/work/app"),
                                         gate: gate, repoAt: { url in seen.mutate { $0.append(url.path) }; return InMemoryRepo() })
        XCTAssertEqual(seen.value.sorted(), ["/abs", "/work/app/Packages/Core"])
    }
}

final class Locked<Value>: @unchecked Sendable {
    // @unchecked: all access goes through `lock`.
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value { lock.lock(); defer { lock.unlock() }; return stored }
    func mutate(_ body: (inout Value) -> Void) { lock.lock(); defer { lock.unlock() }; body(&stored) }
}
