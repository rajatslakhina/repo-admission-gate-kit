import XCTest
@testable import RepoAdmission

final class RedTeamFixtureTests: XCTestCase {
    /// Recall AND precision against the fixture: every planted vector found,
    /// no decoy (commented-out plugin, string containing "Process(", `.sample`
    /// hook, pbxproj comment mentioning a script phase, non-shell alias,
    /// CompilerPluginSupport import, a `.plugin(` in a non-manifest source)
    /// reported.
    func testStandardScannerFindsExactlyThePlantedVectors() throws {
        let audit = RedTeamFixture.audit(try RepoScanner.standard.scan(RedTeamFixture.repo))
        XCTAssertEqual(audit.missing, [], "missed: \(audit.missing)")
        XCTAssertEqual(audit.unexpected, [], "decoys reported: \(audit.unexpected)")
        XCTAssertTrue(audit.passed)
        XCTAssertEqual(RedTeamFixture.expected.count, 35)
    }

    /// The audit must be able to fail. Remove any one family's scanner and the
    /// audit reports that family's vectors as missing — so the test above is
    /// not passing because the audit is vacuous.
    func testAuditFailsWhenAnyScannerIsRemoved() throws {
        let standard = RepoScanner.standard.scanners
        XCTAssertEqual(standard.count, 5)
        for removed in standard.indices {
            var scanners = standard
            let name = scanners.remove(at: removed).name
            let audit = RedTeamFixture.audit(try RepoScanner(scanners: scanners).scan(RedTeamFixture.repo))
            XCTAssertFalse(audit.passed, "removing \(name) went unnoticed")
            XCTAssertFalse(audit.missing.isEmpty, "removing \(name) went unnoticed")
        }
    }

    /// A scanner that over-reports (treats `.sample` hooks as live) must fail
    /// the precision half of the audit.
    func testAuditFailsOnAnOverReportingScanner() throws {
        struct SampleHooksToo: VectorScanner {
            let name = "over-reporting"
            func scan(_ context: ScanContext) -> [ExecutionVector] {
                context.files { $0.hasSuffix(".sample") }.map {
                    ExecutionVector(vectorClass: .gitHook, subject: PathText.lastComponent($0), path: $0,
                                    payload: "", firedBy: [.gitCommit])
                }
            }
        }
        let scanner = RepoScanner(scanners: RepoScanner.standard.scanners + [SampleHooksToo()])
        let audit = RedTeamFixture.audit(try scanner.scan(RedTeamFixture.repo))
        XCTAssertEqual(audit.unexpected.map(\.subject), ["pre-commit.sample"])
    }

    func testEveryFamilyIsExercised() {
        let families = Set(RedTeamFixture.expected.map(\.vectorClass.family))
        XCTAssertEqual(families, Set(VectorFamily.allCases).subtracting([.scanIntegrity]))
    }

    func testInventoryDigestIsStableAndContentSensitive() throws {
        let a = try RepoScanner.standard.scan(RedTeamFixture.repo)
        let b = try RepoScanner.standard.scan(RedTeamFixture.repo)
        XCTAssertEqual(a.digest, b.digest)
        let edited = try RepoScanner.standard.scan(RedTeamFixture.repoAfterUpstreamEdit(RedTeamFixture.repo))
        XCTAssertNotEqual(a.digest, edited.digest)
        // Same identities, different content: the edit is a content change, not a new vector.
        XCTAssertEqual(a.vectors.map(\.id), edited.vectors.map(\.id))
    }

    func testEmptyRepositoryHasNoVectors() throws {
        let inventory = try RepoScanner.standard.scan(InMemoryRepo())
        XCTAssertTrue(inventory.vectors.isEmpty)
        XCTAssertEqual(inventory.entriesScanned, 0)
        let assessment = AdmissionPolicy.strict.evaluate(inventory)
        XCTAssertTrue(assessment.blocking.isEmpty)
        XCTAssertTrue(assessment.pendingApproval.isEmpty)
    }
}
