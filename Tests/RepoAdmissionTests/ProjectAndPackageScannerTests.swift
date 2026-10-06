import XCTest
@testable import RepoAdmission

final class OpenStepPlistParserTests: XCTestCase {
    func testParsesTheShapesPbxprojUses() throws {
        let text = """
        // !$*UTF8*$!
        { a = 1; /* c */ b = "q\\"uo\\nted"; c = (x, "y", ); d = {e = f;}; g = <0aFF>; h = $SRCROOT/x-y.z; }
        """
        let root = try OpenStepPlistParser.parse(Array(text.utf8)).dictionary
        XCTAssertEqual(root?["a"], .string("1"))
        XCTAssertEqual(root?["b"], .string("q\"uo\nted"))
        XCTAssertEqual(root?["c"], .array([.string("x"), .string("y")]))
        XCTAssertEqual(root?["d"]?.dictionary?["e"], .string("f"))
        XCTAssertEqual(root?["g"], .data([0x0A, 0xFF]))
        XCTAssertEqual(root?["h"], .string("$SRCROOT/x-y.z"))
    }

    func testHostileNestingThrowsInsteadOfOverflowingTheStack() {
        let deep = String(repeating: "(", count: 100_000)
        XCTAssertThrowsError(try OpenStepPlistParser.parse(Array(deep.utf8))) { error in
            XCTAssertEqual(error as? PlistParseError, .tooDeep(limit: OpenStepPlistParser.maxDepth))
        }
    }

    func testTruncatedInputThrows() {
        for text in ["{", "{ a = ", "{ a = \"x", "(a, b", "<0a", "", "{ a = b }", "{ = b; }"] {
            XCTAssertThrowsError(try OpenStepPlistParser.parse(Array(text.utf8)), "accepted: \(text)")
        }
    }

    func testUnparseableProjectFailsClosed() throws {
        let repo = InMemoryRepo(files: ["App.xcodeproj/project.pbxproj": "{ objects = { X = { isa = PBXShellScriptBuildPhase; "])
        let vectors = try RepoScanner.standard.scan(repo).vectors
        XCTAssertEqual(vectors.map(\.vectorClass), [.unscannableControlFile])
        XCTAssertEqual(vectors.first?.firedBy, Set(Trigger.allCases))
    }

    func testJSONProjectFormatFailsClosed() throws {
        let repo = InMemoryRepo(files: ["App.xcodeproj/project.xcproj": "{\"objects\": {}}"])
        XCTAssertEqual(try RepoScanner.standard.scan(repo).vectors.map(\.vectorClass), [.unscannableControlFile])
    }

    func testBuildSettingsThatSwapToolsOrLoadPluginsAreVectors() {
        XCTAssertTrue(XcodeProjectScanner.isExecutingSetting("CC", "/tmp/cc"))
        XCTAssertTrue(XcodeProjectScanner.isExecutingSetting("OTHER_LDFLAGS", "-Xclang -load -Xclang x.so"))
        XCTAssertFalse(XcodeProjectScanner.isExecutingSetting("OTHER_SWIFT_FLAGS", "-warnings-as-errors"))
        XCTAssertFalse(XcodeProjectScanner.isExecutingSetting("SWIFT_VERSION", "6.0"))
        XCTAssertFalse(XcodeProjectScanner.isExecutingSetting("CC", ""))
    }

    func testSchemeEntitiesAreDecoded() {
        let scripts = XcodeProjectScanner.schemeScripts(#"<A scriptText = "a &amp;&amp; b&#10;c &quot;d&quot;"/><B scriptText='e'/>"#)
        XCTAssertEqual(scripts, ["a && b\nc \"d\"", "e"])
    }
}

final class ManifestScannerTests: XCTestCase {
    func testLexerSeparatesCodeCommentsAndStrings() {
        let lexed = SwiftLexed(#"""
        let a = "x(\(f("y)")))" /* /* nested */ .macro( */ // .plugin(
        let b = #"raw "quote" \(notInterpolated)"#
        let c = """
          multi "line"
          """
        Process()
        """#)
        let code = lexed.codeString
        XCTAssertFalse(code.contains(".macro("))
        XCTAssertFalse(code.contains(".plugin("))
        XCTAssertTrue(code.contains("Process()"))
        XCTAssertTrue(code.contains("f("), "interpolated code is scanned as code")
        XCTAssertTrue(lexed.literals.contains(#"raw "quote" \(notInterpolated)"#))
        XCTAssertTrue(lexed.literals.contains { $0.contains(#"multi "line""#) })
    }

    func testUnterminatedConstructsNeverTrap() {
        for text in ["\"", "#\"", "\"\"\"", "/*", "\"\\(", "\"\\", "#", "\\(", "\"\\(\"\\(\"\\(", "/", "#/", "x = /"] {
            _ = SwiftLexed(text)
        }
        XCTAssertEqual(SwiftLexed("\"abc").literals, ["abc"])
        XCTAssertEqual(SwiftLexed("/* never closed .macro(").codeString, " ")
    }

    /// Legal Swift spellings that a `name(`-only scanner misses.
    func testSpacedCallsRegexLiteralsAndRegistryPackages() throws {
        let manifest = """
        import PackageDescription
        let r = /"/; let p = Process()
        let half = 10 / 2
        let ext = #/a"b/#
        let package = Package(name: "X", dependencies: [.package(id: "acme.lib", exact: "1.0.0")],
            targets: [.macro (name: "M"), .plugin\t(name: "P", capability: .buildTool()),
                      .target(name: "T", swiftSettings: [.unsafeFlags (["-Xfrontend", "-load-plugin-executable"])])])
        """
        let subjects = Set(try RepoScanner.standard.scan(InMemoryRepo(files: ["Package.swift": manifest])).vectors
            .map { "\($0.vectorClass.rawValue) \($0.subject)" })
        XCTAssertTrue(subjects.isSuperset(of: ["macroTarget M", "buildToolPlugin P", "manifestSideEffect Process",
                                               "unsafeFlags -Xfrontend -load-plugin-executable", "remotePackage acme.lib"]),
                      "\(subjects)")
        // `.packageX(` is not `.package(`.
        XCTAssertTrue(CallFinder(code: Array(".packageX(url: 1)")).arguments(of: ".package").isEmpty)
    }

    func testComputedPackageGraphFromManifestResolvedAndProject() throws {
        let inventory = try RepoScanner.standard.scan(RedTeamFixture.repo)
        let packages = Dictionary(uniqueKeysWithValues: inventory.vectors.filter { $0.vectorClass == .remotePackage }
            .map { ($0.subject, $0.pinnedRevision) })
        XCTAssertEqual(packages.keys.sorted(), ["acme.telemetry", "codegen-tools", "swift-format-plugin", "swift-syntax", "telemetry-kit"])
        XCTAssertEqual(packages["acme.telemetry"], .some(nil), "a registry package has no git revision to pin")
        XCTAssertEqual(packages["swift-syntax"], RedTeamFixture.swiftSyntaxRevision)
        XCTAssertEqual(packages["codegen-tools"], .some(nil), "branch-tracked and not in Package.resolved: unpinned")
        XCTAssertEqual(packages["swift-format-plugin"], "1111111111111111111111111111111111111111",
                       "a transitive pin is still code that builds")
    }

    func testDisagreeingLockfilesUnpinThePackage() throws {
        func resolved(_ rev: String) -> String {
            #"{"pins":[{"identity":"a","location":"https://x/a.git","state":{"revision":"\#(rev)"}}],"version":2}"#
        }
        let repo = InMemoryRepo(files: [
            "Package.resolved": resolved("1111"),
            "App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved": resolved("2222"),
        ])
        let vector = try RepoScanner.standard.scan(repo).vectors.first { $0.vectorClass == .remotePackage }
        XCTAssertEqual(vector?.subject, "a")
        XCTAssertNil(vector?.pinnedRevision)
    }

    func testVersion1ResolvedAndGarbageResolved() throws {
        let v1 = #"{"object":{"pins":[{"package":"A","repositoryURL":"https://x/Swift-A.git","state":{"revision":"abc"}}]},"version":1}"#
        let pinned = try RepoScanner.standard.scan(InMemoryRepo(files: ["Package.resolved": v1])).vectors
        XCTAssertEqual(pinned.map(\.subject), ["swift-a"])
        XCTAssertEqual(pinned.first?.pinnedRevision, "abc")
        let garbage = try RepoScanner.standard.scan(InMemoryRepo(files: ["Package.resolved": "{"])).vectors
        XCTAssertEqual(garbage.map(\.vectorClass), [.unscannableControlFile])
    }

    func testIdentityRule() {
        XCTAssertEqual(PackageManifestScanner.identity(fromURL: "https://github.com/Apple/Swift-Collections.git"), "swift-collections")
        XCTAssertEqual(PackageManifestScanner.identity(fromURL: "git@github.com:a/b"), "b")
        XCTAssertEqual(PackageManifestScanner.identity(fromURL: ""), "")
    }

    /// Dogfooding: this library's own manifest has nothing but the baseline
    /// manifest-evaluation vector. If someone adds a plugin, a macro, a remote
    /// dependency or a side effect to Package.swift, this fails.
    func testThisPackagesOwnManifestHasNoExecutionVectors() throws {
        let manifestURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Package.swift")
        let text = try String(contentsOf: manifestURL, encoding: .utf8)
        let vectors = try RepoScanner.standard.scan(InMemoryRepo(files: ["Package.swift": text])).vectors
        XCTAssertEqual(vectors.map(\.vectorClass), [.manifestEvaluation])
    }
}

final class ScanIntegrityTests: XCTestCase {
    func testOversizedControlFileIsReportedNotSkipped() throws {
        let scanner = RepoScanner(scanners: RepoScanner.standard.scanners, limits: ScanLimits(maxFileBytes: 16))
        let repo = InMemoryRepo(files: ["App.xcodeproj/project.pbxproj": String(repeating: " ", count: 17) + "{}"])
        let vectors = try scanner.scan(repo).vectors
        XCTAssertEqual(vectors.map(\.vectorClass), [.unscannableControlFile])
        XCTAssertTrue(vectors.first?.evidence.contains("over the 16-byte scan limit") ?? false)
    }

    func testSymlinkedControlFileIsReportedNotFollowed() throws {
        let repo = InMemoryRepo(symlinks: ["Package.swift": "/etc/elsewhere/Package.swift"])
        let vectors = try RepoScanner.standard.scan(repo).vectors
        XCTAssertEqual(vectors.map(\.vectorClass), [.unscannableControlFile])
    }

    func testDirectoryRepoOnARealFileSystem() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ra-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        for (path, text) in RedTeamFixture.repo.files {
            let url = root.appendingPathComponent(path)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(text).write(to: url)
        }
        // Skipped directories are never descended into, and symlinks are not followed.
        let objects = root.appendingPathComponent(".git/objects/aa")
        try FileManager.default.createDirectory(at: objects, withIntermediateDirectories: true)
        try Data("[core]\nfsmonitor = x\n".utf8).write(to: objects.appendingPathComponent("config"))
        try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("link").path, withDestinationPath: "/etc")

        let disk = try RepoScanner.standard.scan(DirectoryRepo(root: root))
        let memory = try RepoScanner.standard.scan(RedTeamFixture.repo)
        XCTAssertEqual(disk.vectors, memory.vectors, "the scanner sees the same tree the same way on disk and in memory")
        XCTAssertTrue(RedTeamFixture.audit(disk).passed)

        let capped = DirectoryRepo(root: root, limits: ScanLimits(maxEntries: 3))
        XCTAssertThrowsError(try capped.entries()) { error in
            XCTAssertEqual(error as? RepoReadError, .enumerationLimitExceeded(limit: 3))
        }
    }
}
