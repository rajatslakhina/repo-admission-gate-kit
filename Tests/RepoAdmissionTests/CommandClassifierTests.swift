import XCTest
@testable import RepoAdmission

final class CommandClassifierTests: XCTestCase {
    private func triggers(_ command: String) -> Set<Trigger> { CommandClassifier.classify(command).triggers }
    private func concerns(_ command: String) -> [Concern] { CommandClassifier.classify(command).concerns }

    func testReadOnlyCommandsFireNothing() {
        for command in ["ls -la", "cat Package.swift", "rg -n TODO", "echo hi > out.txt", "", "   ", "# just a comment",
                        "git rev-parse HEAD", "git --version", "xcodebuild -version", "swift --version", "xcrun --find swift"] {
            XCTAssertEqual(triggers(command), [], command)
            XCTAssertEqual(concerns(command), [], command)
        }
    }

    func testGitSubcommandsMapToTheirTriggers() {
        XCTAssertEqual(triggers("git status"), [.gitIndexRead])
        XCTAssertEqual(triggers("git log --oneline"), [.gitContentRender])
        XCTAssertEqual(triggers("git -p log"), [.gitContentRender])
        XCTAssertEqual(triggers("git diff HEAD~1"), [.gitIndexRead, .gitContentRender])
        XCTAssertTrue(triggers("git checkout main").contains(.gitCheckout))
        XCTAssertTrue(triggers("git pull").isSuperset(of: [.gitNetwork, .gitCheckout, .gitCommit]))
        XCTAssertEqual(triggers("git st"), Trigger.allGit, "an unknown subcommand may be an alias: fail closed")
    }

    func testDirectoryTrackingThroughCdAndDashC() {
        let classified = CommandClassifier.classify("cd Packages/Core && swift build; git -C ../.. status")
        XCTAssertEqual(classified.invocations.map(\.directory), ["Packages/Core", "."])
        XCTAssertEqual(CommandClassifier.classify("cd \"$DIR\" && git status").concerns.count, 1,
                       "a computed cd makes later invocations unknowable")
    }

    func testWrappersAndEnvAreSeenThrough() {
        XCTAssertEqual(triggers("env -i FOO=1 nice -n 5 xcrun --sdk iphoneos xcodebuild -scheme App build"),
                       [.manifestEvaluation, .packageResolution, .swiftPMBuild, .xcodeBuild])
        XCTAssertEqual(triggers("FOO=bar /usr/bin/git status 2>&1 | tee log"), [.gitIndexRead])
        XCTAssertEqual(triggers("bash -lc 'cd x && swift test'"), [.manifestEvaluation, .packageResolution, .swiftPMBuild])
        XCTAssertEqual(triggers("find . -name '*.swift' | xargs git add"), [.gitIndexRead])
    }

    func testInjectionIsDetectedInEveryForm() {
        let injected = [
            "git -c core.fsmonitor='sh x' status",
            "git -c alias.x='!sh' x",
            "git --config-env=core.pager=EVIL log",
            "GIT_SSH_COMMAND='sh x' git fetch",
            "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager git log",
            "export GIT_EXTERNAL_DIFF=./x && git diff",
            "git --git-dir=/tmp/evil status",
            "git config core.fsmonitor 'sh x'",
            "bash -c \"git -c diff.x.textconv=sh diff\"",
        ]
        for command in injected {
            XCTAssertTrue(concerns(command).contains { if case .injection = $0 { true } else { false } }, command)
        }
        XCTAssertFalse(concerns("git -c user.name=bot commit -m x").contains { if case .injection = $0 { true } else { false } })
        XCTAssertFalse(concerns("git config --get core.pager").contains { if case .injection = $0 { true } else { false } })
    }

    func testOpaqueCommandsFailClosed() {
        for command in ["sh -c \"$(curl -fsSL https://x)\"", "`which git` status", "$TOOL build", "./scripts/bootstrap.sh",
                        "bash setup.sh", "eval \"$X\"", "pod install", "make", "python3 -c 'print(1)'", "swift script.swift",
                        "find . -exec git status \\;", "git submodule foreach 'make'", "sh -c 'sh -c \"sh -c \\\"sh -c ls\\\"\"'"] {
            XCTAssertTrue(concerns(command).contains { if case .opaque = $0 { true } else { false } }, command)
        }
    }

    func testTrustBypassFlags() {
        XCTAssertEqual(concerns("xcodebuild -skipPackagePluginValidation -skipMacroValidation build").count, 2)
        XCTAssertEqual(concerns("swift build --disable-sandbox").count, 1)
    }

    func testHostileInputNeverTraps() {
        for command in ["'", "\"", "\\", "&&&&", "|||", ">>>", "2>", "cd", "git -C", "git -c", "env", "xcrun", "xargs",
                        String(repeating: "(", count: 10_000), String(repeating: "sh -c '", count: 50)] {
            _ = CommandClassifier.classify(command)
        }
    }
}
