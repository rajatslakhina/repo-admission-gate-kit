/// What the policy says about one vector.
public enum Disposition: String, Codable, Sendable, Comparable, CaseIterable {
    /// Reviewed or inherently acceptable.
    case allow
    /// Blocks the triggers that fire it until a human approves the repository's
    /// current executable surface (bound to its digest).
    case requireApproval
    /// Blocks the triggers that fire it, and no approval unblocks it. The only
    /// way through is to sanitize (remove) the vector or change the policy.
    case deny

    public static func < (lhs: Disposition, rhs: Disposition) -> Bool {
        lhs.severity < rhs.severity
    }

    private var severity: Int {
        switch self {
        case .allow: 0
        case .requireApproval: 1
        case .deny: 2
        }
    }
}

/// An allow-listed package: identity plus the exact git revision.
/// For a source package, the commit hash *is* the content address.
public struct PackagePin: Hashable, Codable, Sendable {
    public let identity: String
    public let revision: String

    public init(identity: String, revision: String) {
        self.identity = identity.lowercased()
        self.revision = revision.lowercased()
    }
}

/// A declarative admission policy, intended to be checked into the team's
/// tooling repository and reviewed like code.
///
/// Allow-lists are always content-addressed: script phases, build rules,
/// legacy targets, scheme actions and hooks by SHA-256 of their content;
/// packages by identity *and* revision. Nothing is ever allowed by name.
public struct AdmissionPolicy: Sendable, Equatable, Codable {
    public var rules: [VectorClass: Disposition]
    public var allowedDigests: Set<Digest>
    public var allowedPackages: Set<PackagePin>

    public init(rules: [VectorClass: Disposition], allowedDigests: Set<Digest> = [], allowedPackages: Set<PackagePin> = []) {
        self.rules = rules
        self.allowedDigests = allowedDigests
        self.allowedPackages = allowedPackages
    }

    /// A class with no rule is `.requireApproval` — new vector classes added in
    /// a later version of this library fail closed under an old policy file.
    public func rule(for vectorClass: VectorClass) -> Disposition {
        rules[vectorClass] ?? .requireApproval
    }

    /// The default. Git-level command execution is denied outright (it has no
    /// legitimate reason to arrive inside a repository, and it is sanitizable);
    /// project-level build code needs a human to approve its digest; manifest
    /// evaluation is allowed because SwiftPM sandboxes it on macOS.
    public static let strict = AdmissionPolicy(rules: [
        .gitConfigCommand: .deny,
        .gitConfigInclude: .deny,
        .gitHooksPathRedirect: .requireApproval,
        .gitDirRedirect: .deny,
        .gitHook: .requireApproval,
        .gitAttributeDriverDefined: .deny,
        .gitAttributeDriverLatent: .allow,
        .gitSubmoduleInjection: .deny,
        .manifestEvaluation: .allow,
        .versionSpecificManifest: .requireApproval,
        .manifestSideEffect: .requireApproval,
        .buildToolPlugin: .requireApproval,
        .commandPlugin: .requireApproval,
        .macroTarget: .requireApproval,
        .unsafeFlags: .requireApproval,
        .binaryTarget: .requireApproval,
        .remotePackage: .requireApproval,
        .localPackage: .requireApproval,
        .scriptPhase: .requireApproval,
        .buildRule: .requireApproval,
        .legacyTarget: .requireApproval,
        .schemeAction: .requireApproval,
        .buildSetting: .requireApproval,
        .unscannableControlFile: .requireApproval,
    ])

    /// For Linux hosts and CI runners, where SwiftPM evaluates manifests with
    /// no sandbox: evaluation itself needs approval, and a latent attribute
    /// driver is treated as if the host's global config might define it.
    public static let paranoid: AdmissionPolicy = {
        var policy = AdmissionPolicy.strict
        policy.rules[.manifestEvaluation] = .requireApproval
        policy.rules[.gitAttributeDriverLatent] = .requireApproval
        policy.rules[.unscannableControlFile] = .deny
        return policy
    }()

    public func evaluate(_ inventory: Inventory) -> Assessment {
        Assessment(inventory: inventory, findings: inventory.vectors.map(finding))
    }

    func finding(for vector: ExecutionVector) -> Finding {
        let base = rule(for: vector.vectorClass)
        if vector.vectorClass.isDigestAllowListable, allowedDigests.contains(vector.digest) {
            return Finding(vector: vector, disposition: .allow,
                           reason: "content digest \(vector.digest.short) is on the policy allow-list")
        }
        if vector.vectorClass == .remotePackage {
            guard let revision = vector.pinnedRevision else {
                return Finding(vector: vector, disposition: max(base, .requireApproval),
                               reason: "not pinned by any Package.resolved (or two lockfiles disagree): whatever resolves today is what runs")
            }
            if allowedPackages.contains(PackagePin(identity: vector.subject, revision: revision)) {
                return Finding(vector: vector, disposition: .allow,
                               reason: "\(vector.subject) @ \(revision.prefix(12)) is on the policy allow-list")
            }
            return Finding(vector: vector, disposition: base,
                           reason: "pinned at \(revision.prefix(12)), but that revision is not on the allow-list; it may vend macros or plugins")
        }
        return Finding(vector: vector, disposition: base, reason: Self.explanation(vector.vectorClass))
    }

    static func explanation(_ vectorClass: VectorClass) -> String {
        switch vectorClass {
        case .gitConfigCommand: "a git config value that git executes as a command"
        case .gitConfigInclude: "pulls in config from a file this scan did not read"
        case .gitHooksPathRedirect: "points git's hooks at a directory inside the tree"
        case .gitDirRedirect: "git's metadata or work tree lives outside what was scanned"
        case .gitHook: "an active hook script"
        case .gitAttributeDriverDefined: "an attribute wired to a driver this repo's config defines as a command"
        case .gitAttributeDriverLatent: "an attribute naming a driver the repo does not define (the host's config may)"
        case .gitSubmoduleInjection: "a submodule url/path that runs a command or injects an option"
        case .manifestEvaluation: "Package.swift is Swift code that runs on load (sandboxed on macOS only)"
        case .versionSpecificManifest: "SwiftPM may evaluate this instead of the Package.swift you reviewed"
        case .manifestSideEffect: "the manifest reaches for process, file, network or environment APIs"
        case .buildToolPlugin: "plugin code that runs during every build"
        case .commandPlugin: "plugin code that runs on `swift package <verb>`"
        case .macroTarget: "a compiler plugin that runs while compiling"
        case .unsafeFlags: "raw compiler/linker flags (can load compiler plugins)"
        case .binaryTarget: "a prebuilt binary linked into the build"
        case .remotePackage: "a remote package whose code builds and may run at build time"
        case .localPackage: "a path dependency outside the scanned tree"
        case .scriptPhase: "a Run Script build phase"
        case .buildRule: "a custom build rule script"
        case .legacyTarget: "an external build tool invocation"
        case .schemeAction: "a scheme pre/post action script"
        case .buildSetting: "a build setting that swaps the compiler/linker or loads compiler plugins"
        case .unscannableControlFile: "a control file the scanner could not inspect"
        }
    }

    // Codable: encode the rules as a string-keyed object so a policy file is
    // readable JSON, not an alternating key/value array.
    private enum CodingKeys: String, CodingKey { case rules, allowedDigests, allowedPackages }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let raw = try container.decode([String: Disposition].self, forKey: .rules)
        var rules: [VectorClass: Disposition] = [:]
        for (key, value) in raw {
            guard let vectorClass = VectorClass(rawValue: key) else {
                throw DecodingError.dataCorruptedError(forKey: .rules, in: container,
                                                       debugDescription: "unknown vector class '\(key)'")
            }
            rules[vectorClass] = value
        }
        self.rules = rules
        self.allowedDigests = try container.decodeIfPresent(Set<Digest>.self, forKey: .allowedDigests) ?? []
        self.allowedPackages = try container.decodeIfPresent(Set<PackagePin>.self, forKey: .allowedPackages) ?? []
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Dictionary(uniqueKeysWithValues: rules.map { ($0.key.rawValue, $0.value) }), forKey: .rules)
        try container.encode(allowedDigests.sorted(), forKey: .allowedDigests)
        try container.encode(allowedPackages.sorted { ($0.identity, $0.revision) < ($1.identity, $1.revision) }, forKey: .allowedPackages)
    }
}

public struct Finding: Hashable, Sendable {
    public let vector: ExecutionVector
    public let disposition: Disposition
    public let reason: String
}

/// A policy applied to an inventory.
public struct Assessment: Sendable, Equatable {
    public let inventory: Inventory
    public let findings: [Finding]

    /// Findings no approval can clear.
    public var blocking: [Finding] { findings.filter { $0.disposition == .deny } }
    /// Findings an approval clears.
    public var pendingApproval: [Finding] { findings.filter { $0.disposition == .requireApproval } }

    /// What an approval binds to: every approval-requiring vector's identity
    /// *and content*. Editing one byte of an approved script phase, adding a
    /// hook, or moving a package pin changes this digest, which silently voids
    /// the approval — the gate then re-quarantines on the next tool call.
    /// Unrelated edits (source files, README) do not.
    public var approvalSurface: Digest {
        Digest.combining(pendingApproval.map { ($0.vector.id, $0.vector.digest) }, domain: "approval-surface/v1")
    }
}
