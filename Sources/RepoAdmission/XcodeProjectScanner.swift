import Foundation

/// A parsed OpenStep-format property list (the format of `project.pbxproj`).
public indirect enum PlistValue: Equatable, Sendable {
    case string(String)
    case array([PlistValue])
    case dictionary([String: PlistValue])
    case data([UInt8])

    public var string: String? { if case .string(let s) = self { return s }; return nil }
    public var dictionary: [String: PlistValue]? { if case .dictionary(let d) = self { return d }; return nil }
    public var array: [PlistValue]? { if case .array(let a) = self { return a }; return nil }
}

public enum PlistParseError: Error, Equatable, Sendable {
    case unexpected(String, offset: Int)
    case unterminated(String, offset: Int)
    case tooDeep(limit: Int)
}

/// A real OpenStep plist parser rather than a regex over `project.pbxproj`.
///
/// Rejected alternative: grepping for `shellScript = "`. A regex has no idea
/// whether it is inside a comment, a string, or a different object, and the
/// pbxproj format allows a script phase's keys in any order and any quoting.
/// The parser is linear-time and nesting is capped (`maxDepth`), so a hostile
/// file of ten thousand `(` throws `tooDeep` instead of overflowing the stack.
public struct OpenStepPlistParser {
    public static let maxDepth = 64
    private let bytes: [UInt8]
    private var pos = 0

    public static func parse(_ bytes: [UInt8]) throws -> PlistValue {
        var parser = OpenStepPlistParser(bytes: bytes)
        parser.skipTrivia()
        let value = try parser.parseValue(depth: 0)
        return value
    }

    private init(bytes: [UInt8]) { self.bytes = bytes }

    private var current: UInt8? { bytes[safe: pos] }

    private mutating func skipTrivia() {
        while let c = current {
            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { pos += 1; continue }
            if c == 0x2F, bytes[safe: pos + 1] == 0x2F {  // //
                while let d = current, d != 0x0A { pos += 1; _ = d }
                continue
            }
            if c == 0x2F, bytes[safe: pos + 1] == 0x2A {  // /*
                pos += 2
                while pos < bytes.count, !(bytes[pos] == 0x2A && bytes[safe: pos + 1] == 0x2F) { pos += 1 }
                pos = min(bytes.count, pos + 2)
                continue
            }
            return
        }
    }

    private mutating func parseValue(depth: Int) throws -> PlistValue {
        guard depth < Self.maxDepth else { throw PlistParseError.tooDeep(limit: Self.maxDepth) }
        skipTrivia()
        guard let c = current else { throw PlistParseError.unterminated("value", offset: pos) }
        switch c {
        case 0x7B: return try parseDictionary(depth: depth)      // {
        case 0x28: return try parseArray(depth: depth)           // (
        case 0x22: return .string(try parseQuoted())             // "
        case 0x3C: return .data(try parseData())                 // <
        default:
            let word = parseUnquoted()
            guard !word.isEmpty else { throw PlistParseError.unexpected(String(UnicodeScalar(c)), offset: pos) }
            return .string(word)
        }
    }

    private mutating func expect(_ byte: UInt8, _ what: String) throws {
        skipTrivia()
        guard current == byte else {
            throw current == nil ? PlistParseError.unterminated(what, offset: pos)
                                 : PlistParseError.unexpected(what, offset: pos)
        }
        pos += 1
    }

    private mutating func parseDictionary(depth: Int) throws -> PlistValue {
        pos += 1
        var dict: [String: PlistValue] = [:]
        while true {
            skipTrivia()
            guard let c = current else { throw PlistParseError.unterminated("dictionary", offset: pos) }
            if c == 0x7D { pos += 1; return .dictionary(dict) }
            guard case .string(let key) = try parseValue(depth: depth + 1) else {
                throw PlistParseError.unexpected("dictionary key", offset: pos)
            }
            try expect(0x3D, "=")
            dict[key] = try parseValue(depth: depth + 1)
            try expect(0x3B, ";")
        }
    }

    private mutating func parseArray(depth: Int) throws -> PlistValue {
        pos += 1
        var items: [PlistValue] = []
        while true {
            skipTrivia()
            guard let c = current else { throw PlistParseError.unterminated("array", offset: pos) }
            if c == 0x29 { pos += 1; return .array(items) }
            items.append(try parseValue(depth: depth + 1))
            skipTrivia()
            if current == 0x2C { pos += 1 } else if current != 0x29 {
                throw PlistParseError.unexpected("array separator", offset: pos)
            }
        }
    }

    private mutating func parseQuoted() throws -> String {
        let start = pos
        pos += 1
        var out: [UInt8] = []
        while let c = current {
            pos += 1
            if c == 0x22 { return String(decoding: out, as: UTF8.self) }
            if c == 0x5C, let e = current {
                pos += 1
                switch e {
                case 0x6E: out.append(0x0A)      // \n
                case 0x74: out.append(0x09)      // \t
                case 0x72: out.append(0x0D)      // \r
                default: out.append(e)           // \" \\ and anything else literally
                }
                continue
            }
            out.append(c)
        }
        throw PlistParseError.unterminated("string", offset: start)
    }

    private mutating func parseUnquoted() -> String {
        var out: [UInt8] = []
        while let c = current, Self.isUnquoted(c) { out.append(c); pos += 1 }
        return String(decoding: out, as: UTF8.self)
    }

    private static func isUnquoted(_ c: UInt8) -> Bool {
        (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
            || c == 0x5F || c == 0x24 || c == 0x2B || c == 0x2F || c == 0x3A || c == 0x2E || c == 0x2D
    }

    private mutating func parseData() throws -> [UInt8] {
        let start = pos
        pos += 1
        var nibbles: [UInt8] = []
        while let c = current {
            pos += 1
            if c == 0x3E {
                var out: [UInt8] = []
                var i = 0
                while i + 1 < nibbles.count { out.append(nibbles[i] << 4 | nibbles[i + 1]); i += 2 }
                return out
            }
            switch c {
            case 0x30...0x39: nibbles.append(c - 0x30)
            case 0x41...0x46: nibbles.append(c - 0x41 + 10)
            case 0x61...0x66: nibbles.append(c - 0x61 + 10)
            case 0x20, 0x09, 0x0A, 0x0D: continue
            default: throw PlistParseError.unexpected("data byte", offset: pos)
            }
        }
        throw PlistParseError.unterminated("data", offset: start)
    }
}

/// `*.xcodeproj/project.pbxproj` and `*.xcscheme`.
public struct XcodeProjectScanner: VectorScanner {
    public let name = "xcode-project"
    public init() {}

    static func isProject(_ path: String) -> Bool {
        PathText.lastComponent(path) == "project.pbxproj" && PathText.directory(path).hasSuffix(".xcodeproj")
    }

    public func scan(_ context: ScanContext) -> [ExecutionVector] {
        var vectors: [ExecutionVector] = []
        for path in context.files(where: Self.isProject) {
            guard let objects = Self.objects(path, context) else { continue }
            for id in objects.keys.sorted() {
                guard let object = objects[id]?.dictionary, let isa = object["isa"]?.string else { continue }
                switch isa {
                case "PBXShellScriptBuildPhase":
                    let name = object["name"]?.string ?? "Run Script"
                    let shell = object["shellPath"]?.string ?? "/bin/sh"
                    let script = object["shellScript"]?.string ?? ""
                    vectors.append(ExecutionVector(
                        vectorClass: .scriptPhase, subject: "\(name) [\(id)]", path: path,
                        payload: "#!\(shell)\n\(script)", firedBy: [.xcodeBuild]))
                case "PBXBuildRule":
                    if let script = object["script"]?.string, !script.trimmingSpaces().isEmpty {
                        let pattern = object["filePatterns"]?.string ?? object["fileType"]?.string ?? "?"
                        vectors.append(ExecutionVector(
                            vectorClass: .buildRule, subject: "\(pattern) [\(id)]", path: path,
                            payload: script, firedBy: [.xcodeBuild]))
                    }
                case "PBXLegacyTarget":
                    let tool = object["buildToolPath"]?.string ?? "?"
                    let args = object["buildArgumentsString"]?.string ?? ""
                    vectors.append(ExecutionVector(
                        vectorClass: .legacyTarget, subject: "\(object["name"]?.string ?? "?") [\(id)]", path: path,
                        payload: "\(tool) \(args)", firedBy: [.xcodeBuild]))
                case "XCLocalSwiftPackageReference":
                    let relative = object["relativePath"]?.string ?? ""
                    let projectDirectory = PathText.directory(PathText.directory(path))
                    if relative.hasPrefix("/") || PathText.normalize(PathText.join(projectDirectory, relative)) == nil {
                        vectors.append(ExecutionVector(
                            vectorClass: .localPackage, subject: relative, path: path,
                            payload: "Xcode local package outside the repository: \(relative)",
                            firedBy: [.manifestEvaluation, .packageResolution, .xcodeBuild]))
                    }
                default:
                    continue
                }
            }
        }

        for path in context.files(where: { $0.hasSuffix(".xcscheme") }) {
            guard let xml = context.text(path) else { continue }
            for (index, script) in Self.schemeScripts(xml).enumerated() {
                vectors.append(ExecutionVector(
                    vectorClass: .schemeAction,
                    subject: "\(PathText.lastComponent(path)) action #\(index + 1)", path: path,
                    payload: script, firedBy: [.xcodeBuild]))
            }
        }
        return vectors
    }

    /// The `objects` table of a pbxproj, or nil (reported) if it cannot be parsed.
    static func objects(_ path: String, _ context: ScanContext) -> [String: PlistValue]? {
        guard let bytes = context.bytes(path) else { return nil }
        do {
            guard let objects = try OpenStepPlistParser.parse(bytes).dictionary?["objects"]?.dictionary else {
                context.reportProblem(path: path, detail: "project.pbxproj has no objects table")
                return nil
            }
            return objects
        } catch {
            // Fail closed: a project we cannot parse is a project whose script
            // phases we cannot see.
            context.reportProblem(path: path, detail: "project.pbxproj could not be parsed: \(error)")
            return nil
        }
    }

    /// Remote packages an Xcode project declares, for the SwiftPM scanner's graph.
    static func remotePackages(_ context: ScanContext) -> [(String, String, String, String)] {
        var result: [(String, String, String, String)] = []
        for path in context.files(where: isProject) {
            guard let objects = objects(path, context) else { continue }
            for id in objects.keys.sorted() {
                guard let object = objects[id]?.dictionary,
                      object["isa"]?.string == "XCRemoteSwiftPackageReference",
                      let url = object["repositoryURL"]?.string else { continue }
                let requirement = object["requirement"]?.dictionary
                let kind = requirement?["kind"]?.string ?? "unspecified"
                let detail = requirement?["minimumVersion"]?.string ?? requirement?["version"]?.string
                    ?? requirement?["branch"]?.string ?? requirement?["revision"]?.string ?? ""
                result.append((PackageManifestScanner.identity(fromURL: url), url, "\(kind) \(detail)", path))
            }
        }
        return result
    }

    /// Every `scriptText` attribute in a scheme (pre/post actions of every action).
    static func schemeScripts(_ xml: String) -> [String] {
        var scripts: [String] = []
        var rest = Substring(xml)
        while let range = rest.range(of: "scriptText") {
            var cursor = range.upperBound
            while cursor < rest.endIndex, rest[cursor] == " " || rest[cursor] == "\n" || rest[cursor] == "\t" {
                cursor = rest.index(after: cursor)
            }
            guard cursor < rest.endIndex, rest[cursor] == "=" else { rest = rest[range.upperBound...]; continue }
            cursor = rest.index(after: cursor)
            while cursor < rest.endIndex, rest[cursor] == " " || rest[cursor] == "\n" || rest[cursor] == "\t" {
                cursor = rest.index(after: cursor)
            }
            guard cursor < rest.endIndex, rest[cursor] == "\"" || rest[cursor] == "'" else {
                rest = rest[range.upperBound...]; continue
            }
            let quote = rest[cursor]
            let start = rest.index(after: cursor)
            guard let end = rest[start...].firstIndex(of: quote) else { break }
            scripts.append(decodeEntities(String(rest[start..<end])))
            rest = rest[rest.index(after: end)...]
        }
        return scripts
    }

    static func decodeEntities(_ text: String) -> String {
        var out = text
        for (entity, value) in [("&quot;", "\""), ("&apos;", "'"), ("&lt;", "<"), ("&gt;", ">"),
                                ("&#10;", "\n"), ("&#13;", "\r"), ("&#9;", "\t"), ("&amp;", "&")] {
            out = out.replacingAll(entity, with: value)
        }
        return out
    }
}

extension String {
    func replacingAll(_ target: String, with replacement: String) -> String {
        guard !target.isEmpty else { return self }
        return components(separatedBy: target).joined(separator: replacement)
    }
}
