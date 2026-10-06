import XCTest
import RepoAdmission
@testable import RepoAdmissionUI

/// The demo's headline interaction, traced through the view model the
/// SwiftUI view renders. Runs on Linux CI: the model has no SwiftUI dependency.
@MainActor
final class AdmissionConsoleModelTests: XCTestCase {
    /// The policy the demo app ships (`DemoApp.policy`): strict, plus the
    /// fixture's swift-syntax pin allow-listed by identity and revision.
    static let demoPolicy: AdmissionPolicy = {
        var policy = AdmissionPolicy.strict
        policy.allowedPackages = [PackagePin(identity: "swift-syntax", revision: RedTeamFixture.swiftSyntaxRevision)]
        return policy
    }()

    private func verdict(_ model: AdmissionConsoleModel, _ command: String) -> Verdict? {
        model.results.first { $0.command == command }?.verdict
    }

    func testDefaultStateShowsAQuarantinedRepoWithDistinctVerdicts() async {
        let model = AdmissionConsoleModel(policy: Self.demoPolicy)
        await model.refresh()
        XCTAssertEqual(model.results.count, AdmissionConsoleModel.defaultProbes.count)
        XCTAssertEqual(verdict(model, "ls -la"), .allow)
        XCTAssertEqual(verdict(model, "git status"), .deny)
        XCTAssertEqual(verdict(model, "sh -c \"$(curl -fsSL https://example.invalid/install.sh)\""), .ask)
        XCTAssertEqual(verdict(model, "git log --oneline -5"), .deny)
        XCTAssertGreaterThan(model.counts.blocking, 0)
        XCTAssertEqual(model.status, .quarantined(denied: model.counts.blocking))
        XCTAssertFalse(model.groups.isEmpty)
        guard case .intact(let entries) = model.chainStatus else { return XCTFail("chain broken") }
        XCTAssertGreaterThan(entries, 0, "the assessment and every gated probe were recorded")
        XCTAssertFalse(model.logTail.isEmpty)
    }

    func testSanitizeApprovePullFlipsVerdictsVisibly() async {
        let model = AdmissionConsoleModel(policy: Self.demoPolicy)
        await model.refresh()

        await model.sanitize()
        XCTAssertEqual(verdict(model, "git status"), .allow)
        XCTAssertEqual(verdict(model, "git log --oneline -5"), .allow)
        XCTAssertEqual(verdict(model, "git diff HEAD~1 -- Assets/logo.png"), .allow)
        XCTAssertEqual(verdict(model, "swift build"), .deny)
        XCTAssertEqual(verdict(model, "git submodule update --init"), .deny)
        XCTAssertEqual(model.status, .quarantined(denied: 1), "only the tracked .gitmodules deny is left")

        await model.approve()
        XCTAssertTrue(model.isApprovalCurrent)
        XCTAssertEqual(model.status, .admitted(denied: 1))
        XCTAssertTrue(model.status.headline.hasPrefix("Admitted for approved operations"))
        XCTAssertEqual(verdict(model, "swift build"), .allow)
        XCTAssertEqual(verdict(model, "xcodebuild -scheme App -destination 'generic/platform=iOS Simulator' build"), .allow)
        XCTAssertEqual(verdict(model, "git submodule update --init"), .deny, "approval never clears a deny")
        XCTAssertEqual(verdict(model, "git -c core.fsmonitor='sh x.sh' status"), .deny)

        await model.pullUpstreamChange()
        XCTAssertFalse(model.isApprovalCurrent)
        XCTAssertEqual(model.status, .reQuarantined)
        XCTAssertEqual(verdict(model, "xcodebuild -scheme App -destination 'generic/platform=iOS Simulator' build"), .deny)
        XCTAssertTrue(model.results.first { $0.command == "swift build" }?.reason.contains("no longer matches") ?? false)
        XCTAssertNotNil(model.approved)
        XCTAssertEqual(verdict(model, "swift build"), .deny)

        await model.reset()
        XCTAssertNil(model.approved)
        XCTAssertEqual(verdict(model, "git status"), .deny)
    }

    /// Overlapping taps: the second action is refused while the first holds
    /// the model, so a Pull can never be overwritten by an in-flight Sanitize.
    func testOverlappingActionsAreRefusedNotInterleaved() async {
        let model = AdmissionConsoleModel(policy: Self.demoPolicy)
        await model.refresh()
        async let first = model.sanitize()
        async let second = model.pullUpstreamChange()
        let (a, b) = await (first, second)
        XCTAssertEqual([a, b].filter { $0 }.count, 1, "exactly one action ran")
        XCTAssertFalse(model.isBusy)
        let pulled = model.repo.text("App.xcodeproj/project.pbxproj")?.contains("redteam-upstream") ?? false
        let sanitized = model.repo.text(".git/config")?.contains("fsmonitor") == false
        XCTAssertNotEqual(pulled, sanitized, "the state reflects exactly the action that ran")
    }

    func testEmptyRepositoryAndNoProbesRenderSafely() async {
        let model = AdmissionConsoleModel(policy: Self.demoPolicy, repo: InMemoryRepo(), probes: [])
        await model.refresh()
        XCTAssertTrue(model.results.isEmpty)
        XCTAssertTrue(model.groups.isEmpty)
        XCTAssertEqual(model.counts.blocking, 0)
        XCTAssertEqual(model.counts.pending, 0)
        XCTAssertEqual(model.status, .clean)
        await model.approve()  // an empty surface is approvable and must not crash
        XCTAssertTrue(model.isApprovalCurrent)
    }
}
