import XCTest
@testable import RepoAdmission

/// Regression tests for the second review round: every input here came back
/// ALLOW (or 0 vectors) against an earlier build while git or SwiftPM really
/// ran the payload.
final class EncodingHardeningTests: XCTestCase {
    private func classes(_ files: [String: String]) throws -> [String] {
        try RepoScanner.standard.scan(InMemoryRepo(files: files)).vectors.map { "\($0.vectorClass.rawValue) \($0.subject)" }
    }

    func testCRLFAndBOMDoNotHideGitConfig() throws {
        XCTAssertEqual(try classes([".git/config": "[core]\r\n\tfsmonitor = sh x\r\n"]), ["gitConfigCommand core.fsmonitor"])
        XCTAssertEqual(try classes([".git/config": "\u{FEFF}[core]\n\tfsmonitor = sh x\n"]), ["gitConfigCommand core.fsmonitor"])
        let crlfSubmodule = try classes([".gitmodules": "[submodule \"x\"]\r\n\turl = ext::sh -c x\r\n"])
        XCTAssertEqual(crlfSubmodule, ["gitSubmoduleInjection submodule.x.url"])
    }

    func testCRLFCombiningMarksAndBackticksDoNotHideManifestCalls() throws {
        let crlf = "// swift-tools-version: 6.0\r\nimport PackageDescription\r\nlet package = Package(name: \"X\", targets: [.plugin(name: \"P\", capability: .buildTool())])\r\n"
        XCTAssertTrue(try classes(["Package.swift": crlf]).contains("buildToolPlugin P"))
        let combining = "let s = \"\u{301}x\"; let t: [Target] = [.plugin(name: \"P\", capability: .buildTool())]\n"
        XCTAssertTrue(try classes(["Package.swift": combining]).contains("buildToolPlugin P"))
        let backticks = "let a = Target.`plugin`(name: \"B\", capability: .buildTool())\nlet f = [.`unsafeFlags`([\"-Xfrontend\"])]\n"
        let found = try classes(["Package.swift": backticks])
        XCTAssertTrue(found.contains("buildToolPlugin B"), "\(found)")
        XCTAssertTrue(found.contains("unsafeFlags -Xfrontend"), "\(found)")
    }

    func testCRLFXcconfigAndScheme() throws {
        XCTAssertTrue(try classes(["Base.xcconfig": "// c\r\nSWIFT_EXEC = /tmp/x\r\n"]).contains("buildSetting SWIFT_EXEC (Base.xcconfig:2)"))
        let scheme = "<ActionContent\r\n scriptText\r\n = \"touch x\">"
        XCTAssertEqual(try classes(["A.xcodeproj/xcshareddata/xcschemes/A.xcscheme": scheme]), ["schemeAction A.xcscheme action #1"])
    }

    func testConditionalKeysAndIndirectFlagsInPbxproj() throws {
        func project(_ settings: String) -> [String: String] {
            ["App.xcodeproj/project.pbxproj": "{ objects = { C1 = { isa = XCBuildConfiguration; name = Debug; buildSettings = { \(settings) }; }; }; }"]
        }
        XCTAssertEqual(try classes(project("\"SWIFT_EXEC[sdk=*]\" = /tmp/evil;")).count, 1)
        XCTAssertEqual(try classes(project("\"OTHER_SWIFT_FLAGS[arch=*]\" = \"-load-plugin-executable x\";")).count, 1)
        XCTAssertEqual(try classes(project("EVIL = \"-load-plugin-executable x\"; OTHER_SWIFT_FLAGS = \"$(EVIL)\";")).count, 1)
        XCTAssertEqual(try classes(project("OTHER_SWIFT_FLAGS = \"$(FROM_XCCONFIG)\";")).count, 1, "unresolvable flags fail closed")
        XCTAssertEqual(try classes(project("OTHER_SWIFT_FLAGS = \"$(inherited) -warnings-as-errors\"; SWIFT_VERSION = 6.0;")), [])
    }

    func testCRLFSanitizeKeepsLineEndingsAndHeader() throws {
        var repo = InMemoryRepo(files: [".git/config": "[core] fsmonitor = evil\r\n\tbare = false\r\n"])
        let plan = SanitizationPlan(assessment: AdmissionPolicy.strict.evaluate(try RepoScanner.standard.scan(repo)), repo: repo)
        try plan.apply(to: &repo)
        XCTAssertEqual(repo.text(".git/config"), "[core]\r\n\tbare = false\r\n")
    }

    func testTotalByteBudgetFailsClosed() throws {
        let scanner = RepoScanner(scanners: RepoScanner.standard.scanners,
                                  limits: ScanLimits(maxFileBytes: 1_000, maxTotalBytes: 30))
        let repo = InMemoryRepo(files: ["Package.swift": String(repeating: " ", count: 25),
                                        "Sub/Package.swift": String(repeating: " ", count: 25)])
        let vectors = try scanner.scan(repo).vectors
        XCTAssertTrue(vectors.contains { $0.vectorClass == .unscannableControlFile }, "\(vectors.map(\.vectorClass))")
    }
}

final class ShellHardeningTests: XCTestCase {
    private func triggers(_ c: String) -> Set<Trigger> { CommandClassifier.classify(c).triggers }
    private func opaque(_ c: String) -> Bool {
        CommandClassifier.classify(c).concerns.contains { if case .opaque = $0 { true } else { false } }
    }
    private func injected(_ c: String) -> Bool {
        CommandClassifier.classify(c).concerns.contains { if case .injection = $0 { true } else { false } }
    }

    func testProgramNameFormsThatHideGit() {
        XCTAssertTrue(opaque("{git,status}"))
        XCTAssertTrue(opaque("/usr/bin/[g]it status"))
        XCTAssertFalse(opaque("[ -f Package.swift ]"), "`[` is the test builtin")
        for command in ["gi\\\nt status", "coproc git status", "exec -a x git status", "bash -c -- 'git status'",
                        "echo status | xargs git", "/usr/lib/git-core/git-status", "flock /tmp/l git status", "setsid git status"] {
            XCTAssertTrue(triggers(command).contains(.gitIndexRead), command)
        }
        XCTAssertTrue(opaque("flock /tmp/l -c 'git status'"))
    }

    func testSwiftPMHelperBinaries() {
        for command in ["swift-build", "swift-test", "swift-package resolve", "xcrun swift-build"] {
            XCTAssertTrue(triggers(command).contains(.manifestEvaluation), command)
        }
    }

    func testDirectoryChangesAreFollowedOrFailClosed() {
        XCTAssertEqual(CommandClassifier.classify("env -C /evil git status").invocations.map(\.directory), ["/evil"])
        XCTAssertEqual(CommandClassifier.classify("env --chdir=sub git status").invocations.map(\.directory), ["sub"])
        XCTAssertEqual(CommandClassifier.classify("swift build --package-path /evil").invocations.map(\.directory), ["/evil"])
        XCTAssertEqual(CommandClassifier.classify("xcodebuild -project /evil/X.xcodeproj build").invocations.map(\.directory), ["/evil"])
        XCTAssertEqual(CommandClassifier.classify("xcodebuild -workspace App.xcworkspace build").invocations.map(\.directory), ["."])
        for command in ["pushd /a && popd && git status", "cd - && git status", "cd ~/evil && git status", "git -C ~/evil status"] {
            XCTAssertTrue(opaque(command), command)
            XCTAssertTrue(CommandClassifier.classify(command).invocations.allSatisfy { $0.directory != "~/evil" }, command)
        }
    }

    func testPlumbingAndHelpTriggers() {
        XCTAssertTrue(triggers("git cat-file --filters HEAD:a.dat").contains(.gitCheckout))
        XCTAssertTrue(triggers("git hash-object a.dat").contains(.gitIndexRead))
        XCTAssertTrue(triggers("git archive HEAD").contains(.gitCheckout))
        XCTAssertTrue(triggers("git config --edit").contains(.gitCommit))
        XCTAssertTrue(triggers("git branch --edit-description").contains(.gitCommit))
        XCTAssertTrue(triggers("git help status").contains(.gitContentRender))
    }

    func testEnvironmentInjection() {
        XCTAssertTrue(injected("GIT_COMMON_DIR=/evil/.git git status"))
        XCTAssertTrue(injected("declare -x GIT_CONFIG_GLOBAL=/evil/cfg; git status"))
        XCTAssertTrue(injected("EDITOR='sh x' git commit"))
        XCTAssertFalse(injected("PAGER=cat git log"), "the standard way to disable a pager is not an injection")
        XCTAssertFalse(injected("GIT_PAGER= git log"))
    }

    func testMoreExecutableConfigKeys() {
        for text in ["[man \"x\"]\ncmd = sh", "[browser \"x\"]\ncmd = sh", "[gpg \"ssh\"]\ndefaultKeyCommand = sh",
                     "[trailer \"t\"]\ncommand = sh", "[sendemail]\ntocmd = sh"] {
            XCTAssertNotNil(GitConfigParser.parse(text).first.flatMap(GitExecKeys.classify), text)
        }
    }
}
