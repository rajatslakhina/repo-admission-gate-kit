/// The agent actions that can make repository-controlled code run.
///
/// A vector is only dangerous to a tool call that *fires* it. Mapping both
/// sides onto this one vocabulary is what lets the gate block
/// `git submodule update` on a repo with a poisoned `.gitmodules` while still
/// letting `ls` and `git log --oneline` through — gating the operation, not
/// quarantining the whole repository.
public enum Trigger: String, Codable, Sendable, CaseIterable, Comparable {
    /// Anything that reads the index: status, diff, add, commit, checkout…
    case gitIndexRead
    /// Rendering file content: diff, log -p, show, blame (textconv, pagers).
    case gitContentRender
    /// Writing the working tree: checkout, switch, reset, clone, pull, merge…
    case gitCheckout
    /// Creating commits or rewriting history: commit, merge, rebase, am…
    case gitCommit
    /// Talking to remotes: fetch, pull, push, clone, submodule, ls-remote.
    case gitNetwork
    /// A git subcommand that is not a built-in — the only way an alias runs.
    case gitAliasOrExternal
    /// Evaluating `Package.swift` (every SwiftPM and Xcode package operation).
    case manifestEvaluation
    /// Fetching and resolving remote packages (which evaluates *their* manifests).
    case packageResolution
    /// Compiling a package: build-tool plugins, macros and command plugins run.
    case swiftPMBuild
    /// Building an Xcode project or workspace: script phases, build rules,
    /// legacy targets and scheme pre/post actions run.
    case xcodeBuild

    public static let allGit: Set<Trigger> = [.gitIndexRead, .gitContentRender, .gitCheckout, .gitCommit, .gitNetwork, .gitAliasOrExternal]

    public static func < (lhs: Trigger, rhs: Trigger) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// The five execution-vector families named in the design, plus one for the
/// scanner's own blind spots.
public enum VectorFamily: String, Codable, Sendable, CaseIterable {
    case gitConfig = "Git config"
    case gitHooks = "Git hooks"
    case gitAttributes = "Git attributes & submodules"
    case swiftPM = "SwiftPM manifest & packages"
    case xcodeProject = "Xcode project & schemes"
    case scanIntegrity = "Scan integrity"
}

/// What kind of execution vector a finding is. Payload-free so it can key a
/// policy table.
public enum VectorClass: String, Codable, Sendable, CaseIterable, Comparable {
    // Git config
    case gitConfigCommand          // a config key whose value is a command git runs
    case gitConfigInclude          // include.path / includeIf: config we cannot see
    case gitHooksPathRedirect      // core.hooksPath pointing hooks into the tree
    case gitDirRedirect            // core.worktree, or a `.git` file pointing elsewhere
    // Hooks
    case gitHook
    // Attributes & submodules
    case gitAttributeDriverDefined // attribute → driver the repo's own config defines
    case gitAttributeDriverLatent  // attribute → driver defined nowhere in the repo
    case gitSubmoduleInjection     // ext:: transport or option-shaped url/path
    // SwiftPM
    case manifestEvaluation
    case versionSpecificManifest   // Package@swift-X.swift: may not be the manifest you read
    case manifestSideEffect        // Process, FileManager, URLSession… inside a manifest
    case buildToolPlugin
    case commandPlugin
    case macroTarget
    case unsafeFlags
    case binaryTarget
    case remotePackage
    case localPackage              // a path dependency that escapes the repository
    // Xcode
    case scriptPhase
    case buildRule
    case legacyTarget
    case schemeAction
    // Integrity
    case unscannableControlFile

    public var family: VectorFamily {
        switch self {
        case .gitConfigCommand, .gitConfigInclude, .gitHooksPathRedirect, .gitDirRedirect: .gitConfig
        case .gitHook: .gitHooks
        case .gitAttributeDriverDefined, .gitAttributeDriverLatent, .gitSubmoduleInjection: .gitAttributes
        case .manifestEvaluation, .versionSpecificManifest, .manifestSideEffect, .buildToolPlugin,
             .commandPlugin, .macroTarget, .unsafeFlags, .binaryTarget, .remotePackage, .localPackage: .swiftPM
        case .scriptPhase, .buildRule, .legacyTarget, .schemeAction: .xcodeProject
        case .unscannableControlFile: .scanIntegrity
        }
    }

    /// Classes whose content can be allow-listed by digest (a reviewed script
    /// is approved by what it says, not by what it is called).
    public var isDigestAllowListable: Bool {
        switch self {
        case .scriptPhase, .buildRule, .legacyTarget, .schemeAction, .gitHook: true
        default: false
        }
    }

    public static func < (lhs: VectorClass, rhs: VectorClass) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// One place in a repository where content the repository controls can run on
/// the machine of whoever builds or operates on it.
public struct ExecutionVector: Hashable, Codable, Sendable, Identifiable {
    public let vectorClass: VectorClass
    /// Key name, hook name, target name, package identity…
    public let subject: String
    /// Repo-relative path of the file the vector was found in.
    public let path: String
    /// 1-based line range in `path`, when meaningful.
    public let lines: ClosedRange<Int>?
    /// Human-readable evidence, truncated to `ExecutionVector.evidenceLimit`.
    public let evidence: String
    /// SHA-256 of the *full* payload (never the truncated evidence).
    public let digest: Digest
    /// Agent actions that make this vector run.
    public let firedBy: Set<Trigger>
    /// For `.remotePackage`: the revision `Package.resolved` pins, if any.
    public let pinnedRevision: String?

    public static let evidenceLimit = 240

    public init(vectorClass: VectorClass, subject: String, path: String, lines: ClosedRange<Int>? = nil,
                payload: String, firedBy: Set<Trigger>, pinnedRevision: String? = nil) {
        self.vectorClass = vectorClass
        self.subject = subject
        self.path = path
        self.lines = lines
        self.digest = .of(payload)
        self.evidence = payload.count > Self.evidenceLimit
            ? String(payload.prefix(Self.evidenceLimit)) + "…"
            : payload
        self.firedBy = firedBy
        self.pinnedRevision = pinnedRevision
    }

    /// Stable identity: class, file, subject and starting line.
    public var id: String {
        "\(vectorClass.rawValue):\(path):\(subject):\(lines?.lowerBound ?? 0)"
    }

    public var family: VectorFamily { vectorClass.family }
}

/// Everything one scan found.
public struct Inventory: Sendable, Equatable {
    public let vectors: [ExecutionVector]
    /// Number of directory entries the scan enumerated.
    public let entriesScanned: Int
    /// Digest over every vector's identity and content.
    public let digest: Digest

    public init(vectors: [ExecutionVector], entriesScanned: Int) {
        // Deduplicate by identity, keep a deterministic order.
        var seen = Set<String>()
        var unique: [ExecutionVector] = []
        for vector in vectors.sorted(by: { $0.id < $1.id }) where seen.insert(vector.id).inserted {
            unique.append(vector)
        }
        self.vectors = unique
        self.entriesScanned = entriesScanned
        self.digest = Digest.combining(unique.map { ($0.id, $0.digest) }, domain: "inventory/v1")
    }

    public func vectors(in family: VectorFamily) -> [ExecutionVector] {
        vectors.filter { $0.family == family }
    }
}
