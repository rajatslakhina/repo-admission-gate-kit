import Foundation

/// One `key = value` from a git-config-format file.
public struct GitConfigEntry: Hashable, Sendable {
    /// Lowercased section name (`core`, `diff`, `filter`…).
    public let section: String
    /// Subsection, case preserved (`[diff "img"]` → `img`).
    public let subsection: String?
    /// Lowercased variable name.
    public let name: String
    /// nil for a bare key (`[core] bare`), which git reads as boolean true.
    public let value: String?
    /// 1-based lines this entry occupies (more than one with `\` continuations).
    public let lines: ClosedRange<Int>

    public var dottedKey: String {
        if let subsection { return "\(section).\(subsection).\(name)" }
        return "\(section).\(name)"
    }
}

/// A git-config parser that follows git's own rules closely enough that an
/// attacker cannot hide a key from it with syntax git accepts: case-insensitive
/// sections and names, `[section "sub"]` and legacy `[section.sub]` headers,
/// a key on the same line as its header, quoted values, `#`/`;` comments,
/// backslash escapes and `\`-newline continuations.
public enum GitConfigParser {
    public static func parse(_ text: String) -> [GitConfigEntry] {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map { line -> [Character] in
            var chars = Array(line)
            if chars.last == "\r" { chars.removeLast() }
            return chars
        }
        var entries: [GitConfigEntry] = []
        var section = ""
        var subsection: String?
        var index = 0
        while index < lines.count {
            let startLine = index + 1
            var line = lines[index]
            index += 1
            var cursor = skipSpaces(line, from: 0)
            guard cursor < line.count else { continue }
            if line[cursor] == "#" || line[cursor] == ";" { continue }

            if line[cursor] == "[" {
                guard let close = headerEnd(line, from: cursor + 1) else { continue }  // malformed: git errors, we skip
                (section, subsection) = parseHeader(Array(line[(cursor + 1)..<close]))
                cursor = skipSpaces(line, from: close + 1)
                guard cursor < line.count, line[cursor] != "#", line[cursor] != ";" else { continue }
            }

            // Variable name.
            var name = ""
            while cursor < line.count, line[cursor].isLetter || line[cursor].isNumber || line[cursor] == "-" {
                name.append(line[cursor])
                cursor += 1
            }
            guard !name.isEmpty else { continue }
            cursor = skipSpaces(line, from: cursor)
            guard cursor < line.count, line[cursor] == "=" else {
                entries.append(GitConfigEntry(section: section, subsection: subsection, name: name.lowercased(),
                                              value: nil, lines: startLine...startLine))
                continue
            }
            cursor = skipSpaces(line, from: cursor + 1)

            // Value, with quotes, escapes, comments and continuations.
            var value = ""
            var pendingSpace = ""
            var inQuote = false
            var endLine = startLine
            scanning: while true {
                guard cursor < line.count else { break scanning }
                let char = line[cursor]
                cursor += 1
                switch char {
                case "\"":
                    value += pendingSpace; pendingSpace = ""
                    inQuote.toggle()
                case "\\":
                    guard cursor < line.count else {
                        // Continuation: the value carries on at the next line.
                        guard index < lines.count else { break scanning }
                        line = lines[index]
                        index += 1
                        endLine = index
                        cursor = 0
                        continue scanning
                    }
                    let escaped = line[cursor]
                    cursor += 1
                    value += pendingSpace; pendingSpace = ""
                    switch escaped {
                    case "n": value.append("\n")
                    case "t": value.append("\t")
                    case "b": if !value.isEmpty { value.removeLast() }
                    default: value.append(escaped)
                    }
                case "#" where !inQuote, ";" where !inQuote:
                    break scanning
                case " " where !inQuote, "\t" where !inQuote:
                    pendingSpace.append(char)
                default:
                    value += pendingSpace; pendingSpace = ""
                    value.append(char)
                }
            }
            entries.append(GitConfigEntry(section: section, subsection: subsection, name: name.lowercased(),
                                          value: value, lines: startLine...endLine))
        }
        return entries
    }

    private static func skipSpaces(_ line: [Character], from start: Int) -> Int {
        var i = max(0, start)
        while i < line.count, line[i] == " " || line[i] == "\t" { i += 1 }
        return i
    }

    /// Index of the `]` closing a header, honouring a quoted subsection.
    private static func headerEnd(_ line: [Character], from start: Int) -> Int? {
        var inQuote = false
        var i = start
        while i < line.count {
            switch line[i] {
            case "\\" where inQuote: i += 1
            case "\"": inQuote.toggle()
            case "]" where !inQuote: return i
            default: break
            }
            i += 1
        }
        return nil
    }

    private static func parseHeader(_ body: [Character]) -> (String, String?) {
        if let quote = body.firstIndex(of: "\"") {
            let sectionName = String(body[..<quote]).trimmingSpaces().lowercased()
            var sub = ""
            var i = quote + 1
            while i < body.count, body[i] != "\"" {
                if body[i] == "\\", i + 1 < body.count { i += 1 }
                sub.append(body[i])
                i += 1
            }
            return (sectionName, sub)
        }
        let text = String(body).trimmingSpaces()
        if let dot = text.firstIndex(of: ".") {
            // Legacy `[section.sub]`: git lowercases the subsection too.
            return (String(text[..<dot]).lowercased(), String(text[text.index(after: dot)...]).lowercased())
        }
        return (text.lowercased(), nil)
    }
}

extension String {
    func trimmingSpaces() -> String {
        var chars = Substring(self)
        while let first = chars.first, first == " " || first == "\t" { chars.removeFirst() }
        while let last = chars.last, last == " " || last == "\t" { chars.removeLast() }
        return String(chars)
    }
}

/// What a git config key does when git reads it, if it executes anything.
enum GitExecKeys {
    static let booleanLiterals: Set<String> = ["true", "false", "yes", "no", "on", "off", "1", "0", ""]

    /// Hooks fire on commit-like, checkout-like and network operations.
    static let hookTriggers: Set<Trigger> = [.gitCommit, .gitCheckout, .gitNetwork]
    static let filterTriggers: Set<Trigger> = [.gitCheckout, .gitIndexRead, .gitCommit]

    /// Returns the vector class and triggers for an executable key, or nil.
    static func classify(_ entry: GitConfigEntry) -> (VectorClass, Set<Trigger>)? {
        let value = entry.value?.trimmingSpaces() ?? ""
        let isCommandValue = entry.value != nil && !booleanLiterals.contains(value.lowercased())
        switch (entry.section, entry.subsection, entry.name) {
        case ("include", nil, "path"), ("includeif", _, "path"):
            return (.gitConfigInclude, Trigger.allGit)
        case ("core", nil, "hookspath"):
            return entry.value == nil ? nil : (.gitHooksPathRedirect, hookTriggers)
        case ("core", nil, "worktree"):
            return entry.value == nil ? nil : (.gitDirRedirect, Trigger.allGit)
        case ("core", nil, "fsmonitor"):
            // `true` selects git's built-in daemon; anything else is a command.
            return isCommandValue ? (.gitConfigCommand, [.gitIndexRead]) : nil
        case ("core", nil, "sshcommand"), ("core", nil, "gitproxy"), ("core", nil, "askpass"),
             ("uploadpack", nil, "packobjectshook"), ("remote", _, "uploadpack"), ("remote", _, "receivepack"):
            return isCommandValue ? (.gitConfigCommand, [.gitNetwork]) : nil
        case ("credential", _, "helper"):
            return isCommandValue ? (.gitConfigCommand, [.gitNetwork]) : nil
        case ("protocol", _, "allow") where ["always", "user"].contains(value.lowercased()):
            // `protocol.ext.allow=always` enables the ext:: transport, which is
            // "run this command and speak git over its stdio".
            return entry.subsection == nil || entry.subsection == "ext" ? (.gitConfigCommand, [.gitNetwork]) : nil
        case ("core", nil, "pager"), ("pager", _, _), ("interactive", nil, "difffilter"):
            return isCommandValue ? (.gitConfigCommand, [.gitContentRender]) : nil
        case ("core", nil, "editor"), ("sequence", nil, "editor"):
            return isCommandValue ? (.gitConfigCommand, [.gitCommit]) : nil
        case ("gpg", _, "program"):
            return isCommandValue ? (.gitConfigCommand, [.gitCommit, .gitContentRender]) : nil
        case ("diff", nil, "external"), ("diff", .some(_), "textconv"), ("diff", .some(_), "command"),
             ("difftool", .some(_), "cmd"), ("mergetool", .some(_), "cmd"):
            return isCommandValue ? (.gitConfigCommand, [.gitContentRender]) : nil
        case ("filter", .some(_), "clean"), ("filter", .some(_), "smudge"), ("filter", .some(_), "process"):
            return isCommandValue ? (.gitConfigCommand, filterTriggers) : nil
        case ("merge", .some(_), "driver"):
            return isCommandValue ? (.gitConfigCommand, [.gitCommit, .gitCheckout]) : nil
        case ("alias", _, _) where value.hasPrefix("!"):
            // Aliases cannot shadow built-ins, so a shell alias only runs when
            // the agent invokes that alias name.
            return (.gitConfigCommand, [.gitAliasOrExternal])
        case ("submodule", .some(_), "update") where value.hasPrefix("!"):
            return (.gitConfigCommand, [.gitNetwork, .gitCheckout])
        default:
            return nil
        }
    }
}

/// `.git/config`, and the `.git` *file* form that redirects git elsewhere.
public struct GitConfigScanner: VectorScanner {
    public let name = "git-config"
    public init() {}

    public func scan(_ context: ScanContext) -> [ExecutionVector] {
        var vectors: [ExecutionVector] = []

        // A `.git` that is a file, not a directory: `gitdir: <path>`. If that
        // path leaves the tree, every config/hook git will use lives somewhere
        // this scan cannot see.
        if context.entries.contains(where: { $0.path == ".git" }), let pointer = context.text(".git") {
            let target = pointer.replacingFirst("gitdir:", with: "").trimmingSpaces()
                .split(separator: "\n").first.map(String.init) ?? ""
            if target.hasPrefix("/") || PathText.normalize(target) == nil {
                vectors.append(ExecutionVector(
                    vectorClass: .gitDirRedirect, subject: "gitdir → \(target)", path: ".git",
                    lines: 1...1, payload: pointer, firedBy: Trigger.allGit))
            }
        }

        for entry in context.gitConfig {
            guard let (vectorClass, triggers) = GitExecKeys.classify(entry) else { continue }
            vectors.append(ExecutionVector(
                vectorClass: vectorClass, subject: entry.dottedKey, path: ".git/config",
                lines: entry.lines, payload: "\(entry.dottedKey) = \(entry.value ?? "")", firedBy: triggers))
        }
        return vectors
    }
}

/// Active hooks in `.git/hooks`, plus hooks in a tracked directory that
/// `core.hooksPath` points git at.
public struct GitHooksScanner: VectorScanner {
    public let name = "git-hooks"
    public init() {}

    static func triggers(forHook hook: String) -> Set<Trigger> {
        switch hook {
        case "pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase",
             "post-rewrite", "pre-merge-commit", "post-merge", "applypatch-msg", "pre-applypatch", "post-applypatch":
            return [.gitCommit]
        case "post-checkout":
            return [.gitCheckout]
        case "pre-push", "pre-receive", "update", "post-receive", "post-update", "push-to-checkout", "proc-receive":
            return [.gitNetwork]
        case "fsmonitor-watchman":
            return [.gitIndexRead]
        case "reference-transaction":
            return [.gitCommit, .gitCheckout, .gitNetwork]
        default:
            return Trigger.allGit
        }
    }

    public func scan(_ context: ScanContext) -> [ExecutionVector] {
        var directories = [".git/hooks"]
        if let hooksPath = context.gitConfig.last(where: { $0.section == "core" && $0.subsection == nil && $0.name == "hookspath" })?.value,
           !hooksPath.hasPrefix("/"), let normalized = PathText.normalize(hooksPath), !normalized.isEmpty {
            directories.append(normalized)
        }
        var vectors: [ExecutionVector] = []
        for directory in directories {
            let hooks = context.files { path in
                PathText.directory(path) == directory && !path.hasSuffix(".sample")
            }
            for path in hooks {
                let hook = PathText.lastComponent(path)
                let body = context.text(path) ?? ""
                vectors.append(ExecutionVector(
                    vectorClass: .gitHook, subject: hook, path: path, payload: body,
                    firedBy: Self.triggers(forHook: hook)))
            }
        }
        return vectors
    }
}

/// `.gitattributes` (anywhere in the tree), `.git/info/attributes`, and
/// `.gitmodules`.
///
/// An attribute is only as dangerous as the driver it names. `*.png diff=img`
/// is inert unless something defines `diff.img.textconv`; this scanner
/// cross-references the repo's own config to tell a *defined* (reachable)
/// driver from a *latent* one, which may be defined in the user's global config
/// — outside anything a repository gate can or should judge.
public struct GitAttributesScanner: VectorScanner {
    public let name = "git-attributes"
    public init() {}

    static let driverKeys: [String: Set<String>] = [
        "filter": ["clean", "smudge", "process"],
        "diff": ["textconv", "command"],
        "merge": ["driver"],
    ]

    public func scan(_ context: ScanContext) -> [ExecutionVector] {
        var vectors: [ExecutionVector] = []
        let attributeFiles = context.files { path in
            PathText.lastComponent(path) == ".gitattributes" && !path.hasPrefix(".git/") || path == ".git/info/attributes"
        }
        for path in attributeFiles {
            guard let text = context.text(path) else { continue }
            for (offset, rawLine) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
                let line = String(rawLine).trimmingSpaces()
                guard !line.isEmpty, !line.hasPrefix("#") else { continue }
                let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                for token in tokens.dropFirst() {
                    guard let eq = token.firstIndex(of: "=") else { continue }
                    let kind = String(token[..<eq])
                    let driver = String(token[token.index(after: eq)...])
                    guard let execKeys = Self.driverKeys[kind], !driver.isEmpty else { continue }
                    let definition = context.gitConfig.first {
                        $0.section == kind && $0.subsection == driver && execKeys.contains($0.name)
                    }
                    let triggers: Set<Trigger> = kind == "filter" ? GitExecKeys.filterTriggers
                        : kind == "diff" ? [.gitContentRender] : [.gitCommit, .gitCheckout]
                    let lineNumber = offset + 1
                    vectors.append(ExecutionVector(
                        vectorClass: definition == nil ? .gitAttributeDriverLatent : .gitAttributeDriverDefined,
                        subject: "\(kind)=\(driver)", path: path, lines: lineNumber...lineNumber,
                        payload: definition.map { "\(line)  →  \($0.dottedKey) = \($0.value ?? "")" } ?? line,
                        firedBy: triggers))
                }
            }
        }

        if context.exists(".gitmodules"), let text = context.text(".gitmodules") {
            for entry in GitConfigParser.parse(text) where entry.section == "submodule" {
                let value = entry.value?.trimmingSpaces() ?? ""
                let hostile: Bool
                switch entry.name {
                case "url": hostile = value.lowercased().hasPrefix("ext::") || value.hasPrefix("-")
                case "path": hostile = value.hasPrefix("-") || PathText.normalize(value) == nil || value.hasPrefix("/")
                case "update": hostile = value.hasPrefix("!")
                default: hostile = false
                }
                guard hostile else { continue }
                vectors.append(ExecutionVector(
                    vectorClass: .gitSubmoduleInjection, subject: entry.dottedKey, path: ".gitmodules",
                    lines: entry.lines, payload: "\(entry.dottedKey) = \(value)",
                    firedBy: [.gitNetwork, .gitCheckout]))
            }
        }
        return vectors
    }
}

extension String {
    func replacingFirst(_ target: String, with replacement: String) -> String {
        guard let range = range(of: target) else { return self }
        return replacingCharacters(in: range, with: replacement)
    }
}
