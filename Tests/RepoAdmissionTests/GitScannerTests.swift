import XCTest
@testable import RepoAdmission

final class GitConfigParserTests: XCTestCase {
    func testGitSyntaxAnAttackerCouldUseToHideAKey() {
        let text = """
        [CORE]   FsMonitor = "sh x" ; trailing comment
        [core.Legacy]
        \tfoo = bar
        [diff "Img"]
        \ttextconv = a \\
        \t b
        [x]
        \tbare
        \tquoted = "  keep  # this " # but not this
        \tescapes = a\\tb\\"c
        """
        let entries = GitConfigParser.parse(text)
        XCTAssertEqual(entries.count, 6)
        let fsmonitor = entries[safe: 0]
        XCTAssertEqual(fsmonitor?.dottedKey, "core.fsmonitor")
        XCTAssertEqual(fsmonitor?.value, "sh x")
        XCTAssertEqual(entries[safe: 1]?.dottedKey, "core.legacy.foo")
        XCTAssertEqual(entries[safe: 2]?.dottedKey, "diff.Img.textconv", "quoted subsections keep their case")
        XCTAssertEqual(entries[safe: 2]?.value, "a \t b".replacingOccurrences(of: "\t", with: "\t"))
        XCTAssertEqual(entries[safe: 2]?.lines, 5...6, "a continuation spans both lines, so sanitizing removes both")
        XCTAssertNil(entries[safe: 3]?.value, "a bare key is boolean true")
        XCTAssertEqual(entries[safe: 4]?.value, "  keep  # this ")
        XCTAssertEqual(entries[safe: 5]?.value, "a\tb\"c")
    }

    func testMalformedInputNeverTrapsAndKeysStillSurface() {
        for text in ["[", "[core", "[core \"unterminated", "=", "a = \"unterminated", "a = trailing\\", "\\", "[]", "\n\n\r\n", ""] {
            _ = GitConfigParser.parse(text)
        }
        // A malformed header does not hide the keys that follow a good one,
        // and an unterminated quote still yields the value git would read.
        let entries = GitConfigParser.parse("[core\n[core]\nfsmonitor = \"sh x\n")
        XCTAssertEqual(entries.map(\.dottedKey), ["core.fsmonitor"])
        XCTAssertEqual(entries.first?.value, "sh x")
        XCTAssertEqual(GitConfigParser.parse("a = trailing\\").first?.value, "trailing")
    }

    func testExecutableKeyClassification() {
        func classify(_ text: String) -> VectorClass? {
            GitConfigParser.parse(text).first.flatMap(GitExecKeys.classify)?.0
        }
        XCTAssertEqual(classify("[core]\nfsmonitor = /tmp/x"), .gitConfigCommand)
        XCTAssertNil(classify("[core]\nfsmonitor = true"), "true selects git's built-in daemon")
        XCTAssertNil(classify("[core]\nfsmonitor"), "bare key is boolean")
        XCTAssertEqual(classify("[alias]\nx = !rm -rf ~"), .gitConfigCommand)
        XCTAssertNil(classify("[alias]\nlg = log --oneline"), "a non-shell alias runs no command")
        XCTAssertNil(classify("[pager]\nlog = false"))
        XCTAssertEqual(classify("[credential \"https://x\"]\nhelper = !sh"), .gitConfigCommand)
        XCTAssertEqual(classify("[includeIf \"gitdir:~/\"]\npath = x"), .gitConfigInclude)
        XCTAssertEqual(classify("[protocol]\nallow = always"), .gitConfigCommand)
        XCTAssertNil(classify("[protocol \"https\"]\nallow = always"), "only ext:: runs commands")
        XCTAssertEqual(classify("[core]\nworktree = /elsewhere"), .gitDirRedirect)
        XCTAssertNil(classify("[remote \"origin\"]\nurl = https://x"))
    }
}

final class GitScannerTests: XCTestCase {
    func testGitFilePointingOutsideTheTreeIsARedirect() throws {
        let repo = InMemoryRepo(files: [".git": "gitdir: ../../elsewhere/.git\n"])
        let inventory = try RepoScanner.standard.scan(repo)
        XCTAssertEqual(inventory.vectors.map(\.vectorClass), [.gitDirRedirect])
        let inside = InMemoryRepo(files: [".git": "gitdir: .bare\n"])
        XCTAssertTrue(try RepoScanner.standard.scan(inside).vectors.isEmpty, "an in-tree gitdir with no config has nothing to report")
    }

    /// A `.git` *file* pointing at an in-tree directory is where git reads its
    /// config and hooks from — a scanner that only reads `.git/config` sees nothing.
    func testInTreeGitdirConfigWorktreeAndCommondirAreScanned() throws {
        let repo = InMemoryRepo(files: [
            ".git": "gitdir: meta\n",
            "meta/config": "[core]\n\tfsmonitor = sh x\n",
            "meta/config.worktree": "[core]\n\tpager = sh y\n",
            "meta/hooks/post-checkout": "#!/bin/sh\n",
            "meta/commondir": "../shared\n",
            "shared/config": "[diff \"x\"]\n\ttextconv = sh z\n",
            "shared/hooks/pre-commit": "#!/bin/sh\n",
            "a.png": "", ".gitattributes": "*.png diff=x\n",
        ])
        let found = Set(try RepoScanner.standard.scan(repo).vectors.map { "\($0.vectorClass.rawValue) \($0.subject) @\($0.path)" })
        XCTAssertEqual(found, [
            "gitConfigCommand core.fsmonitor @meta/config",
            "gitConfigCommand core.pager @meta/config.worktree",
            "gitConfigCommand diff.x.textconv @shared/config",
            "gitHook post-checkout @meta/hooks/post-checkout",
            "gitHook pre-commit @shared/hooks/pre-commit",
            "gitAttributeDriverDefined diff=x @.gitattributes",
        ])
        let escaping = InMemoryRepo(files: [".git/config": "", ".git/commondir": "/elsewhere\n"])
        XCTAssertEqual(try RepoScanner.standard.scan(escaping).vectors.map(\.vectorClass), [.gitDirRedirect])
    }

    func testAttributeIsDefinedOnlyWhenTheRepoConfigDefinesAnExecutableDriverKey() throws {
        let repo = InMemoryRepo(files: [
            ".git/config": "[filter \"a\"]\n\trequired = true\n[diff \"b\"]\n\ttextconv = x\n",
            ".gitattributes": "*.a filter=a\n*.b diff=b\n",
            "sub/.gitattributes": "*.c merge=c\n",
        ])
        let classes = Dictionary(uniqueKeysWithValues: try RepoScanner.standard.scan(repo).vectors
            .filter { $0.family == .gitAttributes }.map { ($0.subject, $0.vectorClass) })
        XCTAssertEqual(classes["filter=a"], .gitAttributeDriverLatent, "`required` is not a command")
        XCTAssertEqual(classes["diff=b"], .gitAttributeDriverDefined)
        XCTAssertEqual(classes["merge=c"], .gitAttributeDriverLatent, "nested .gitattributes files are scanned too")
    }

    func testHooksPathOutsideTreeIsNotScannedButStillReported() throws {
        let repo = InMemoryRepo(files: [".git/config": "[core]\n\thooksPath = /usr/local/hooks\n"])
        let vectors = try RepoScanner.standard.scan(repo).vectors
        XCTAssertEqual(vectors.map(\.vectorClass), [.gitHooksPathRedirect])
    }

    func testSubmoduleOptionInjection() throws {
        let repo = InMemoryRepo(files: [".gitmodules": "[submodule \"x\"]\n\tpath = -oProxyCommand=sh\n\turl = https://ok\n"])
        XCTAssertEqual(try RepoScanner.standard.scan(repo).vectors.map(\.subject), ["submodule.x.path"])
    }
}
