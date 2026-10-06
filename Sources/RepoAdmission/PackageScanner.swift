import Foundation

/// A Swift source split into code and string literals.
///
/// The manifest scanner must not be fooled in either direction: a `.plugin(`
/// inside a comment is not a plugin, and `"Process("` inside a string is not a
/// process launch. So comments are removed and every string literal is replaced
/// by a placeholder `"§N"` whose text is kept in `literals[N]`.
///
/// Handles `//` and nested `/* */` comments, `"…"` with escapes, `"""` multi-line
/// strings, raw strings (`#"…"#`, any number of `#`) and `\( … )` interpolation
/// (its contents are scanned as code, which is the conservative direction: an
/// API call hidden in an interpolation is still found).
///
/// Rejected alternative: SwiftSyntax. It would parse exactly, but it is a large
/// remote dependency whose own build takes minutes — and a gate that must run
/// *before* any build cannot depend on a build. The cost of the lexical
/// approach is stated in the README: a manifest can build a plugin target from
/// a computed expression the lexer will not evaluate. That case is caught one
/// layer up, because computed manifests need `Foundation`-level APIs the
/// side-effect scan reports.
struct SwiftLexed {
    var code: [Character] = []
    var literals: [String] = []

    init(_ source: String) {
        let chars = Array(source)
        var i = 0
        lex(chars, &i, terminator: nil, depth: 0)
    }

    /// Lex until `terminator` (")" closing an interpolation) at depth 0.
    private mutating func lex(_ s: [Character], _ i: inout Int, terminator: Character?, depth: Int) {
        var parens = 0
        while i < s.count {
            let c = s[i]
            let next = s[safe: i + 1]
            if let terminator, c == terminator, parens == 0 { return }
            if c == "(" { parens += 1 } else if c == ")" { parens = max(0, parens - 1) }

            if c == "/", next == "/" {
                while i < s.count, s[i] != "\n" { i += 1 }
                continue
            }
            if c == "/", next == "*" {
                var nesting = 0
                while i < s.count {
                    if s[i] == "/", s[safe: i + 1] == "*" { nesting += 1; i += 2; continue }
                    if s[i] == "*", s[safe: i + 1] == "/" { nesting -= 1; i += 2; if nesting == 0 { break }; continue }
                    i += 1
                }
                code.append(" ")
                continue
            }
            if c == "#" || c == "\"" {
                // Count raw-string hashes.
                var hashes = 0
                var j = i
                while j < s.count, s[j] == "#" { hashes += 1; j += 1 }
                if j < s.count, s[j] == "\"" {
                    i = j
                    let text = lexString(s, &i, hashes: hashes, depth: depth)
                    code.append(contentsOf: "\"§\(literals.count)\"")
                    literals.append(text)
                    continue
                }
            }
            code.append(c)
            i += 1
        }
    }

    /// `i` points at the opening quote. Returns literal text; leaves `i` after the close.
    private mutating func lexString(_ s: [Character], _ i: inout Int, hashes: Int, depth: Int) -> String {
        let multiline = s[safe: i + 1] == "\"" && s[safe: i + 2] == "\""
        let quoteCount = multiline ? 3 : 1
        i += quoteCount
        var text = ""
        while i < s.count {
            let c = s[i]
            // Closing delimiter: quotes followed by the same number of hashes.
            if c == "\"" {
                var matches = true
                for k in 0..<quoteCount where s[safe: i + k] != "\"" { matches = false }
                for k in 0..<hashes where s[safe: i + quoteCount + k] != "#" { matches = false }
                if matches {
                    i += quoteCount + hashes
                    return text
                }
            }
            if !multiline, c == "\n" { i += 1; return text }  // unterminated: stop at line end
            if c == "\\" {
                var k = 0
                while k < hashes, s[safe: i + 1 + k] == "#" { k += 1 }
                if k == hashes {
                    let escapeIndex = i + 1 + hashes
                    if s[safe: escapeIndex] == "(" {
                        // Interpolation: its contents are code. Bounded depth so a
                        // pathological manifest cannot recurse without limit.
                        i = escapeIndex + 1
                        if depth < 16 {
                            lex(s, &i, terminator: ")", depth: depth + 1)
                        } else {
                            while i < s.count, s[i] != ")" { i += 1 }
                        }
                        i += 1
                        text += "\\(…)"
                        continue
                    }
                    if let escaped = s[safe: escapeIndex] {
                        text.append(escaped == "n" ? "\n" : escaped == "t" ? "\t" : escaped)
                        i = escapeIndex + 1
                        continue
                    }
                }
            }
            text.append(c)
            i += 1
        }
        return text
    }

    var codeString: String { String(code) }

    /// Literal for a `"§N"` placeholder.
    func literal(_ placeholder: Substring) -> String? {
        let digits = placeholder.drop(while: { $0 == "\"" || $0 == "§" }).prefix(while: { $0.isNumber })
        guard let n = Int(digits) else { return nil }
        return literals[safe: n]
    }
}

/// Finds calls in lexed Swift code.
struct CallFinder {
    let code: [Character]

    /// Argument text of every call to `name` (e.g. ".plugin"), with balanced parens.
    func arguments(of name: String) -> [String] {
        let needle = Array(name + "(")
        var results: [String] = []
        var i = 0
        while i + needle.count <= code.count {
            if code[i..<(i + needle.count)].elementsEqual(needle), isBoundary(before: i, name: name) {
                var depth = 1
                var j = i + needle.count
                let start = j
                while j < code.count, depth > 0 {
                    if code[j] == "(" { depth += 1 } else if code[j] == ")" { depth -= 1 }
                    j += 1
                }
                let end = depth == 0 ? j - 1 : j
                results.append(String(code[start..<max(start, end)]))
                i = j
            } else {
                i += 1
            }
        }
        return results
    }

    /// Whether `identifier` appears as a whole word.
    func containsWord(_ identifier: String) -> Bool {
        let needle = Array(identifier)
        var i = 0
        while i + needle.count <= code.count {
            if code[i..<(i + needle.count)].elementsEqual(needle),
               isBoundary(before: i, name: identifier),
               !(code[safe: i + needle.count].map(Self.isIdentifierChar) ?? false) {
                return true
            }
            i += 1
        }
        return false
    }

    private func isBoundary(before index: Int, name: String) -> Bool {
        // ".plugin(" may legally follow anything; a bare identifier must not
        // be the tail of a longer one ("MyProcess(" is not "Process(").
        if name.hasPrefix(".") { return true }
        guard let previous = code[safe: index - 1] else { return true }
        return !Self.isIdentifierChar(previous)
    }

    static func isIdentifierChar(_ c: Character) -> Bool { c.isLetter || c.isNumber || c == "_" }
}

/// `Package.swift`, its version-specific variants, and every `Package.resolved`.
///
/// What runs, and when:
/// * evaluating the manifest is running Swift (sandboxed by SwiftPM on macOS;
///   not on Linux);
/// * build-tool plugins and macros run during the build, command plugins on
///   `swift package <verb>`;
/// * every remote package — including transitive pins that appear only in
///   `Package.resolved` — gets its *own* manifest evaluated at resolution and
///   may vend plugins or macros. Whether it does is unknowable until it is
///   checked out, and checking it out is resolution. So the policy pins every
///   package in the resolved graph by identity and revision.
public struct PackageManifestScanner: VectorScanner {
    public let name = "swiftpm"
    public init() {}

    static let sideEffectAPIs = ["Process", "FileManager", "URLSession", "ProcessInfo", "getenv", "setenv",
                                 "system", "popen", "dlopen", "fopen", "NSTask", "Pipe", "FileHandle"]
    static let allowedImports: Set<String> = ["PackageDescription", "Foundation", "CompilerPluginSupport"]
    static let buildTriggers: Set<Trigger> = [.swiftPMBuild, .xcodeBuild]
    static let manifestTriggers: Set<Trigger> = [.manifestEvaluation, .packageResolution, .swiftPMBuild, .xcodeBuild]

    static func isManifest(_ path: String) -> Bool {
        let file = PathText.lastComponent(path)
        return file == "Package.swift" || (file.hasPrefix("Package@swift-") && file.hasSuffix(".swift"))
    }

    public func scan(_ context: ScanContext) -> [ExecutionVector] {
        var vectors: [ExecutionVector] = []
        var declared: [String: (url: String, requirement: String, path: String)] = [:]

        for path in context.files(where: Self.isManifest) {
            guard let source = context.text(path) else { continue }
            let file = PathText.lastComponent(path)
            if file != "Package.swift" {
                vectors.append(ExecutionVector(
                    vectorClass: .versionSpecificManifest, subject: file, path: path, payload: source,
                    firedBy: Self.manifestTriggers))
            }
            vectors.append(ExecutionVector(
                vectorClass: .manifestEvaluation, subject: file, path: path, payload: source,
                firedBy: Self.manifestTriggers))
            let lexed = SwiftLexed(source)
            let finder = CallFinder(code: lexed.code)
            vectors += scanTargets(finder, lexed, path: path)
            vectors += scanSideEffects(finder, lexed, path: path)
            for args in finder.arguments(of: ".package") {
                if let url = Self.labelled("url", in: args, lexed) {
                    declared[Self.identity(fromURL: url)] = (url, Self.describeRequirement(args, lexed), path)
                } else if let local = Self.labelled("path", in: args, lexed) {
                    let base = PathText.directory(path)
                    if local.hasPrefix("/") || PathText.normalize(PathText.join(base, local)) == nil {
                        vectors.append(ExecutionVector(
                            vectorClass: .localPackage, subject: local, path: path,
                            payload: "path dependency outside the repository: \(local)",
                            firedBy: Self.manifestTriggers))
                    }
                }
            }
        }

        // Xcode-declared packages feed the same graph.
        for (identity, url, requirement, path) in XcodeProjectScanner.remotePackages(context) where declared[identity] == nil {
            declared[identity] = (url, requirement, path)
        }

        // Pins: every Package.resolved in the tree (root, xcodeproj, xcworkspace).
        var pins: [String: (location: String, revision: String?, path: String)] = [:]
        var conflicted = Set<String>()
        for path in context.files(where: { PathText.lastComponent($0) == "Package.resolved" }) {
            guard let bytes = context.bytes(path) else { continue }
            guard let parsed = ResolvedFile.parse(bytes) else {
                context.reportProblem(path: path, detail: "Package.resolved could not be parsed; its pins are unknown")
                continue
            }
            for pin in parsed {
                if let existing = pins[pin.identity], existing.revision != pin.revision {
                    conflicted.insert(pin.identity)  // two lockfiles disagree: trust neither
                }
                pins[pin.identity] = (pin.location, pin.revision, path)
            }
        }

        for identity in Set(declared.keys).union(pins.keys).sorted() {
            let decl = declared[identity]
            let pin = pins[identity]
            let revision = conflicted.contains(identity) ? nil : pin?.revision
            let url = decl?.url ?? pin?.location ?? identity
            let origin = decl == nil ? "transitive (Package.resolved only)" : "declared \(decl?.requirement ?? "")"
            vectors.append(ExecutionVector(
                vectorClass: .remotePackage, subject: identity, path: decl?.path ?? pin?.path ?? "Package.resolved",
                payload: "\(identity) \(url) @ \(revision ?? "UNPINNED") — \(origin)",
                firedBy: [.packageResolution, .swiftPMBuild, .xcodeBuild],
                pinnedRevision: revision))
        }
        return vectors
    }

    private func scanTargets(_ finder: CallFinder, _ lexed: SwiftLexed, path: String) -> [ExecutionVector] {
        var vectors: [ExecutionVector] = []
        for args in finder.arguments(of: ".plugin") {
            let name = Self.labelled("name", in: args, lexed) ?? "?"
            if args.contains("capability:") {
                let isCommand = args.contains(".command(")
                vectors.append(ExecutionVector(
                    vectorClass: isCommand ? .commandPlugin : .buildToolPlugin, subject: name, path: path,
                    payload: ".plugin(\(args))",
                    firedBy: isCommand ? [.swiftPMBuild] : Self.buildTriggers))
            } else if let package = Self.labelled("package", in: args, lexed) {
                // A target *using* another package's plugin: that package's code
                // runs in this build.
                vectors.append(ExecutionVector(
                    vectorClass: .buildToolPlugin, subject: "\(name) (from \(package))", path: path,
                    payload: ".plugin(\(args))", firedBy: Self.buildTriggers))
            }
        }
        for args in finder.arguments(of: ".macro") {
            vectors.append(ExecutionVector(
                vectorClass: .macroTarget, subject: Self.labelled("name", in: args, lexed) ?? "?", path: path,
                payload: ".macro(\(args))", firedBy: Self.buildTriggers))
        }
        for args in finder.arguments(of: ".binaryTarget") {
            vectors.append(ExecutionVector(
                vectorClass: .binaryTarget, subject: Self.labelled("name", in: args, lexed) ?? "?", path: path,
                payload: ".binaryTarget(\(args)) checksum=\(Self.labelled("checksum", in: args, lexed) ?? "none")",
                firedBy: [.packageResolution, .swiftPMBuild, .xcodeBuild]))
        }
        for args in finder.arguments(of: "unsafeFlags") {
            let flags = Self.allLiterals(in: args, lexed).joined(separator: " ")
            vectors.append(ExecutionVector(
                vectorClass: .unsafeFlags, subject: flags.isEmpty ? "unsafeFlags" : flags, path: path,
                payload: "unsafeFlags(\(args)) → \(flags)", firedBy: Self.buildTriggers))
        }
        return vectors
    }

    private func scanSideEffects(_ finder: CallFinder, _ lexed: SwiftLexed, path: String) -> [ExecutionVector] {
        var vectors: [ExecutionVector] = []
        for api in Self.sideEffectAPIs where finder.containsWord(api) {
            vectors.append(ExecutionVector(
                vectorClass: .manifestSideEffect, subject: api, path: path,
                payload: "manifest references \(api)", firedBy: Self.manifestTriggers))
        }
        let code = lexed.codeString
        for line in code.split(separator: "\n") {
            let trimmed = String(line).trimmingSpaces()
            guard trimmed.hasPrefix("import ") || trimmed.hasPrefix("@_exported import ") else { continue }
            let module = trimmed.split(separator: " ").last.map(String.init) ?? ""
            let root = module.split(separator: ".").first.map(String.init) ?? module
            guard !Self.allowedImports.contains(root) else { continue }
            vectors.append(ExecutionVector(
                vectorClass: .manifestSideEffect, subject: "import \(module)", path: path,
                payload: trimmed, firedBy: Self.manifestTriggers))
        }
        return vectors
    }

    /// Value of `label: "§N"` inside an argument list.
    static func labelled(_ label: String, in args: String, _ lexed: SwiftLexed) -> String? {
        let chars = Array(args)
        let needle = Array(label + ":")
        var i = 0
        while i + needle.count <= chars.count {
            if chars[i..<(i + needle.count)].elementsEqual(needle),
               !(chars[safe: i - 1].map(CallFinder.isIdentifierChar) ?? false) {
                var j = i + needle.count
                while j < chars.count, chars[j] == " " || chars[j] == "\n" || chars[j] == "\t" { j += 1 }
                guard j < chars.count, chars[j] == "\"" else { return nil }
                var k = j + 1
                while k < chars.count, chars[k] != "\"" { k += 1 }
                return lexed.literal(Substring(String(chars[j..<min(chars.count, k + 1)])))
            }
            i += 1
        }
        return nil
    }

    static func allLiterals(in args: String, _ lexed: SwiftLexed) -> [String] {
        args.split(separator: "\"").compactMap { piece in
            piece.hasPrefix("§") ? lexed.literal(piece) : nil
        }
    }

    static func describeRequirement(_ args: String, _ lexed: SwiftLexed) -> String {
        for label in ["exact", "from", "branch", "revision"] {
            if let value = labelled(label, in: args, lexed) { return "\(label): \(value)" }
        }
        let literals = allLiterals(in: args, lexed).dropFirst()  // first is the url
        return literals.isEmpty ? "unspecified" : "range: " + literals.joined(separator: " … ")
    }

    /// SwiftPM's identity rule: last path component, minus `.git`, lowercased.
    public static func identity(fromURL url: String) -> String {
        var last = PathText.lastComponent(url.trimmingSpaces())
        if last.lowercased().hasSuffix(".git") { last = String(last.dropLast(4)) }
        return last.lowercased()
    }
}

/// `Package.resolved` v1, v2 and v3.
struct ResolvedFile {
    struct Pin { let identity: String; let location: String; let revision: String? }

    private struct V2: Decodable {
        struct Pin: Decodable {
            let identity: String?
            let location: String?
            let state: State
        }
        let pins: [Pin]
    }
    private struct V1: Decodable {
        struct Object: Decodable { let pins: [Pin] }
        struct Pin: Decodable {
            let package: String?
            let repositoryURL: String?
            let state: State
        }
        let object: Object
    }
    private struct State: Decodable {
        let revision: String?
        let version: String?
        let branch: String?
    }

    static func parse(_ bytes: [UInt8]) -> [Pin]? {
        let data = Data(bytes)
        let decoder = JSONDecoder()
        if let v2 = try? decoder.decode(V2.self, from: data) {
            return v2.pins.map { pin in
                let location = pin.location ?? ""
                return Pin(identity: (pin.identity ?? PackageManifestScanner.identity(fromURL: location)).lowercased(),
                           location: location, revision: pin.state.revision)
            }
        }
        if let v1 = try? decoder.decode(V1.self, from: data) {
            return v1.object.pins.map { pin in
                let location = pin.repositoryURL ?? ""
                return Pin(identity: PackageManifestScanner.identity(fromURL: location),
                           location: location, revision: pin.state.revision)
            }
        }
        return nil
    }
}
