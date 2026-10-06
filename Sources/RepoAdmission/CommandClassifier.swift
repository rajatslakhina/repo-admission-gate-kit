/// One program invocation found inside a shell command.
public struct Invocation: Hashable, Sendable {
    public let program: String
    public let arguments: [String]
    /// Directory the invocation runs in, relative to the hook's cwd ("." for
    /// the cwd itself). Absolute when the command used an absolute path.
    public let directory: String
    public let triggers: Set<Trigger>
}

/// A reason the classifier refuses to vouch for a command.
public enum Concern: Hashable, Sendable {
    /// The command itself sets a git exec key or exec env var. Always denied:
    /// no repository state can make it safe.
    case injection(String)
    /// The command runs something whose behaviour the classifier cannot know
    /// (command substitution, `eval`, a repo script, `pod install`…).
    case opaque(String)
    /// A flag that disables a toolchain's own trust prompt.
    case trustBypass(String)

    public var message: String {
        switch self {
        case .injection(let m), .opaque(let m), .trustBypass(let m): m
        }
    }
}

public struct ClassifiedCommand: Sendable, Equatable {
    public var invocations: [Invocation] = []
    public var concerns: [Concern] = []

    public var triggers: Set<Trigger> { invocations.reduce(into: []) { $0.formUnion($1.triggers) } }
}

/// Classifies a `Bash` tool call into the triggers it fires.
///
/// This is deliberately not a shell. It tokenises enough of POSIX sh — quotes,
/// escapes, `&& || ; | &`, subshell parens, redirections, env-assignment
/// prefixes, `cd`, wrapper programs, nested `sh -c` — to find every program
/// the line can start, and it fails *closed*: anything it cannot see through
/// (`$(…)`, backticks, a variable in program position, `eval`, a repo-local
/// script, nesting beyond `maxNesting`) becomes an `.opaque` concern, which the
/// gate turns into an `ask`, never an `allow`.
public enum CommandClassifier {
    public static let maxNesting = 3

    public static func classify(_ command: String) -> ClassifiedCommand {
        var result = ClassifiedCommand()
        classify(command, directory: ".", depth: 0, into: &result)
        return result
    }

    // MARK: Tokeniser

    enum Token: Equatable {
        case word(String, dynamic: Bool)   // dynamic: contained $VAR, $(…) or `…`
        case separator
        case redirect
    }

    static func tokenize(_ command: String, concerns: inout [Concern]) -> [Token] {
        var tokens: [Token] = []
        var word = ""
        var inWord = false
        var dynamic = false
        var chars = Array(command)[...]

        func flush() {
            if inWord { tokens.append(.word(word, dynamic: dynamic)) }
            word = ""; inWord = false; dynamic = false
        }

        while let c = chars.first {
            chars = chars.dropFirst()
            switch c {
            case " ", "\t":
                flush()
            case "\n", ";", "&", "|", "(", ")":
                flush()
                if c == "&", chars.first == ">" { tokens.append(.redirect); chars = chars.dropFirst(); continue }
                tokens.append(.separator)
                // Collapse &&, ||
                if (c == "&" || c == "|"), chars.first == c { chars = chars.dropFirst() }
            case ">", "<":
                // A bare fd number before the operator ("2>") belongs to it.
                if inWord, !word.isEmpty, word.allSatisfy(\.isNumber), !dynamic { word = ""; inWord = false }
                flush()
                while let n = chars.first, n == ">" || n == "<" || n == "&" || n == "|" { chars = chars.dropFirst() }
                tokens.append(.redirect)
            case "#" where !inWord:
                // Comment to end of line.
                while let n = chars.first, n != "\n" { chars = chars.dropFirst() }
            case "'":
                inWord = true
                while let n = chars.first, n != "'" { word.append(n); chars = chars.dropFirst() }
                chars = chars.dropFirst()
            case "\"":
                inWord = true
                while let n = chars.first, n != "\"" {
                    chars = chars.dropFirst()
                    if n == "\\", let escaped = chars.first, "\"\\$`\n".contains(escaped) {
                        word.append(escaped); chars = chars.dropFirst(); continue
                    }
                    if n == "$" || n == "`" { dynamic = true }
                    word.append(n)
                }
                chars = chars.dropFirst()
            case "\\":
                inWord = true
                if let escaped = chars.first { word.append(escaped); chars = chars.dropFirst() }
            case "$", "`":
                inWord = true
                dynamic = true
                if c == "`" || chars.first == "(" {
                    concerns.append(.opaque("command substitution — the command it runs is only known at run time"))
                }
                word.append(c)
            default:
                inWord = true
                word.append(c)
            }
        }
        flush()
        return tokens
    }

    // MARK: Classification

    static func classify(_ command: String, directory: String, depth: Int, into result: inout ClassifiedCommand) {
        guard depth <= maxNesting else {
            result.concerns.append(.opaque("shell nesting deeper than \(maxNesting) levels"))
            return
        }
        let tokens = tokenize(command, concerns: &result.concerns)
        var cwd: String? = directory
        var segment: [(String, Bool)] = []
        var skipNext = false

        func finishSegment() {
            defer { segment = [] }
            guard !segment.isEmpty else { return }
            classifySegment(segment, cwd: &cwd, depth: depth, into: &result)
        }

        for token in tokens {
            switch token {
            case .separator:
                finishSegment()
            case .redirect:
                skipNext = true
            case .word(let text, let dynamic):
                if skipNext { skipNext = false; continue }
                segment.append((text, dynamic))
            }
        }
        finishSegment()
    }

    static let gitEnvInjections: Set<String> = [
        "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
        "GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_ASKPASS", "SSH_ASKPASS",
        "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER", "GIT_EXEC_PATH", "GIT_PROXY_COMMAND",
        "GIT_TEMPLATE_DIR", "GIT_DIR", "GIT_WORK_TREE",
    ]

    static let wrappers: Set<String> = ["env", "sudo", "time", "nice", "nohup", "command", "exec", "xcrun", "caffeinate", "arch"]
    static let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "fish"]
    static let interpreters: Set<String> = ["python", "python3", "ruby", "node", "perl", "swift-frontend", "osascript"]
    static let repoCodeRunners: [String: String] = [
        "pod": "CocoaPods evaluates the Podfile, which is Ruby",
        "bundle": "Bundler evaluates the Gemfile, which is Ruby",
        "fastlane": "fastlane evaluates the Fastfile, which is Ruby",
        "make": "make runs the repository's Makefile recipes",
        "tuist": "Tuist evaluates Project.swift manifests",
        "xcodegen": "XcodeGen runs project.yml pre/post-generation commands",
        "carthage": "Carthage builds dependency projects, running their script phases",
        "npm": "npm runs package.json lifecycle scripts",
        "yarn": "Yarn runs package.json lifecycle scripts",
        "pnpm": "pnpm runs package.json lifecycle scripts",
        "just": "just runs the repository's justfile recipes",
        "mise": "mise can run tasks and hooks from the repository's config",
        "direnv": "direnv evaluates the repository's .envrc",
        "eval": "eval runs a string as shell code",
        "source": "source runs a file as shell code",
        ".": "`.` runs a file as shell code",
    ]

    private static func classifySegment(_ rawSegment: [(String, Bool)], cwd: inout String?, depth: Int,
                                        into result: inout ClassifiedCommand) {
        var words = rawSegment[...]

        // Leading VAR=value assignments.
        while let (word, _) = words.first, let eq = word.firstIndex(of: "="),
              word[..<eq].allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" }), !word[..<eq].isEmpty {
            checkEnvAssignment(String(word[..<eq]), into: &result)
            words = words.dropFirst()
        }

        // Wrapper programs: skip them and their options.
        while let (word, _) = words.first, wrappers.contains(PathText.lastComponent(word)) {
            let wrapper = PathText.lastComponent(word)
            words = words.dropFirst()
            if wrapper == "xcrun", words.contains(where: { $0.0 == "--find" || $0.0 == "-f" || $0.0 == "--show-sdk-path" }) {
                return  // xcrun only locating a tool
            }
            while let (option, _) = words.first, option.hasPrefix("-") || (wrapper == "env" && option.contains("=")) {
                if wrapper == "env", let eq = option.firstIndex(of: "="), !option.hasPrefix("-") {
                    checkEnvAssignment(String(option[..<eq]), into: &result)
                }
                words = words.dropFirst()
                // Options that take a value.
                if ["-n", "--sdk", "-sdk", "--toolchain", "-u", "-g", "-C", "--chdir"].contains(option) {
                    words = words.dropFirst()
                }
            }
        }

        guard let (programWord, programDynamic) = words.first else { return }
        let arguments = words.dropFirst().map(\.0)
        if programDynamic {
            result.concerns.append(.opaque("program name is computed at run time: \(programWord)"))
            return
        }
        guard let directory = cwd else {
            result.concerns.append(.opaque("working directory became unknowable earlier in the command"))
            return
        }
        let program = PathText.lastComponent(programWord)

        // A path to a program inside the tree is repository code.
        if programWord.contains("/"), !programWord.hasPrefix("/") {
            result.concerns.append(.opaque("runs a repository file directly: \(programWord)"))
            return
        }

        switch program {
        case "cd", "pushd":
            if let target = words.dropFirst().first {
                cwd = target.1 ? nil : resolve(directory, target.0)
            } else {
                cwd = nil  // `cd` alone goes to $HOME: outside anything we scanned
            }
        case "export":
            for argument in arguments {
                if let eq = argument.firstIndex(of: "=") { checkEnvAssignment(String(argument[..<eq]), into: &result) }
            }
        case "git":
            classifyGit(arguments, directory: directory, into: &result)
        case "swift":
            classifySwift(arguments, directory: directory, into: &result)
        case "xcodebuild":
            classifyXcodebuild(arguments, directory: directory, into: &result)
        case "swiftc":
            if arguments.contains(where: { $0.hasPrefix("-load-plugin") || $0.hasPrefix("-plugin-path") }) {
                result.concerns.append(.opaque("swiftc is loading compiler plugins named on the command line"))
            }
        case "xargs":
            let rest = arguments.drop(while: { $0.hasPrefix("-") })
            if !rest.isEmpty {
                classify(rest.map(shellQuote).joined(separator: " "), directory: directory, depth: depth + 1, into: &result)
            }
        case "find":
            if arguments.contains(where: { ["-exec", "-execdir", "-ok", "-okdir"].contains($0) }) {
                result.concerns.append(.opaque("find -exec runs a command per file"))
            }
        default:
            if shells.contains(program) {
                if let flag = arguments.firstIndex(where: { $0.hasPrefix("-") && $0.contains("c") && !$0.hasPrefix("--") }),
                   let script = arguments[safe: flag + 1] {
                    classify(script, directory: directory, depth: depth + 1, into: &result)
                } else {
                    result.concerns.append(.opaque("\(program) runs a script or stdin the classifier cannot read"))
                }
            } else if interpreters.contains(program) {
                if !arguments.isEmpty, !arguments.allSatisfy({ $0 == "--version" || $0 == "-V" }) {
                    result.concerns.append(.opaque("\(program) runs code the classifier cannot read"))
                }
            } else if let reason = repoCodeRunners[program] {
                result.concerns.append(.opaque(reason))
            }
        }
    }

    private static func checkEnvAssignment(_ name: String, into result: inout ClassifiedCommand) {
        if gitEnvInjections.contains(name) || name.hasPrefix("GIT_CONFIG_KEY_") || name.hasPrefix("GIT_CONFIG_VALUE_") {
            result.concerns.append(.injection("sets \(name), which makes git run a command or read config this gate did not scan"))
        }
    }

    static func resolve(_ base: String, _ path: String) -> String {
        if path.hasPrefix("/") { return path }
        if path == "~" || path.hasPrefix("~/") { return path }
        let joined = base == "." ? path : "\(base)/\(path)"
        if base.hasPrefix("/") { return joined }
        return PathText.normalize(joined).map { $0.isEmpty ? "." : $0 } ?? joined
    }

    static func shellQuote(_ word: String) -> String {
        "'" + word.replacingAll("'", with: "'\\''") + "'"
    }

    // MARK: git

    static let gitSubcommandTriggers: [String: Set<Trigger>] = {
        let render: Set<Trigger> = [.gitIndexRead, .gitContentRender]
        let checkout: Set<Trigger> = [.gitIndexRead, .gitCheckout]
        let commit: Set<Trigger> = [.gitIndexRead, .gitCommit, .gitContentRender]
        let integrate: Set<Trigger> = [.gitIndexRead, .gitCheckout, .gitCommit]
        let network: Set<Trigger> = [.gitNetwork]
        var table: [String: Set<Trigger>] = [:]
        for name in ["status", "add", "rm", "mv", "ls-files", "update-index", "clean", "describe", "check-ignore", "check-attr", "commit-graph"] {
            table[name] = [.gitIndexRead]
        }
        for name in ["diff", "grep", "difftool"] {
            table[name] = render
        }
        // History rendering reads objects, not the index: textconv and pagers
        // can run, the fsmonitor cannot.
        for name in ["show", "log", "blame", "annotate", "range-diff", "format-patch", "shortlog", "whatchanged"] {
            table[name] = [.gitContentRender]
        }
        for name in ["checkout", "switch", "restore", "reset", "stash", "worktree", "sparse-checkout", "read-tree", "checkout-index", "mergetool"] {
            table[name] = checkout
        }
        for name in ["commit", "tag", "notes", "revert", "commit-tree"] { table[name] = commit }
        for name in ["merge", "rebase", "cherry-pick", "am", "apply", "bisect"] { table[name] = integrate }
        for name in ["fetch", "push", "ls-remote", "remote", "send-pack", "fetch-pack", "archive"] { table[name] = network }
        for name in ["pull", "clone", "submodule"] { table[name] = integrate.union(network) }
        for name in ["rev-parse", "branch", "config", "cat-file", "rev-list", "for-each-ref", "show-ref", "symbolic-ref",
                     "hash-object", "ls-tree", "merge-base", "name-rev", "var", "version", "help", "init", "count-objects",
                     "fsck", "gc", "reflog", "verify-commit", "verify-tag", "show-branch", "cherry"] {
            table[name] = []
        }
        // Commands that read the index as a side effect.
        table["branch"] = []
        table["gc"] = [.gitIndexRead]
        return table
    }()

    /// `git` options that consume the next word.
    static let gitOptionsWithValue: Set<String> = ["-C", "-c", "--git-dir", "--work-tree", "--namespace",
                                                    "--exec-path", "--config-env", "--super-prefix"]

    private static func classifyGit(_ args: [String], directory: String, into result: inout ClassifiedCommand) {
        var dir = directory
        var triggers: Set<Trigger> = []
        var index = 0
        var subcommand: String?
        while index < args.count {
            let arg = args[index]
            if arg == "-C", let value = args[safe: index + 1] {
                dir = resolve(dir, value); index += 2; continue
            }
            if arg == "-c" || arg.hasPrefix("--config-env") {
                let assignment = arg == "-c" ? (args[safe: index + 1] ?? "") : String(arg.drop(while: { $0 != "=" }).dropFirst())
                inspectInlineConfig(assignment, into: &result)
                index += arg == "-c" || arg == "--config-env" ? 2 : 1
                continue
            }
            if arg.hasPrefix("--git-dir") || arg.hasPrefix("--work-tree") || arg.hasPrefix("--exec-path") {
                result.concerns.append(.injection("\(arg) points git at metadata or programs this gate did not scan"))
                index += arg.contains("=") ? 1 : 2
                continue
            }
            if arg == "-p" || arg == "--paginate" { triggers.insert(.gitContentRender); index += 1; continue }
            if arg.hasPrefix("-") {
                index += gitOptionsWithValue.contains(arg) ? 2 : 1
                continue
            }
            subcommand = arg
            break
        }
        guard let sub = subcommand else {
            result.invocations.append(Invocation(program: "git", arguments: args, directory: dir, triggers: triggers))
            return
        }
        if let known = gitSubcommandTriggers[sub] {
            triggers.formUnion(known)
            // `git log -p`/`--patch` renders diffs; plain `git log` still runs pagers.
            if sub == "config" {
                // `git config core.fsmonitor "<cmd>"` plants the vector this gate
                // exists to catch; an agent writing it is the same injection.
                let rest = args.drop(while: { $0 != "config" }).dropFirst().filter { !$0.hasPrefix("-") }
                if let key = rest.first, rest.count >= 2, let value = rest.dropFirst().first {
                    inspectInlineConfig("\(key)=\(value)", into: &result)
                }
            }
            if sub == "submodule", args.contains("foreach") {
                result.concerns.append(.opaque("git submodule foreach runs an arbitrary command in each submodule"))
            }
        } else {
            // Not a built-in we know: an alias or a git-<name> program on PATH.
            // Fail closed across every git trigger.
            triggers.formUnion(Trigger.allGit)
        }
        result.invocations.append(Invocation(program: "git", arguments: args, directory: dir, triggers: triggers))
    }

    private static func inspectInlineConfig(_ assignment: String, into result: inout ClassifiedCommand) {
        let key = String(assignment.prefix(while: { $0 != "=" }))
        let value = assignment.contains("=") ? String(assignment.drop(while: { $0 != "=" }).dropFirst()) : nil
        let parts = key.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 2, let first = parts.first, let last = parts.last else { return }
        let subsection = parts.count > 2 ? parts.dropFirst().dropLast().joined(separator: ".") : nil
        let entry = GitConfigEntry(section: first.lowercased(), subsection: subsection, name: last.lowercased(),
                                   value: value, lines: 1...1)
        if GitExecKeys.classify(entry) != nil {
            result.concerns.append(.injection("inline config `\(key)` makes git run a command"))
        }
    }

    // MARK: swift / xcodebuild

    private static func classifySwift(_ args: [String], directory: String, into result: inout ClassifiedCommand) {
        let positional = args.filter { !$0.hasPrefix("-") }
        let all: Set<Trigger> = [.manifestEvaluation, .packageResolution, .swiftPMBuild]
        var triggers: Set<Trigger> = []
        switch positional.first {
        case "build", "test", "run":
            triggers = all
        case "package":
            switch positional[safe: 1] {
            case "resolve", "update", "fetch", "show-dependencies", "edit", "unedit", "archive-source":
                triggers = [.manifestEvaluation, .packageResolution]
            case "describe", "dump-package", "dump-pif", "tools-version", "completion-tool":
                triggers = [.manifestEvaluation]
            case "clean", "reset", "purge-cache", "init", "compute-checksum", "config", "help":
                triggers = []
            default:
                // `swift package <verb>` where verb is a command plugin.
                triggers = all
            }
        case let first? where first.hasSuffix(".swift"):
            result.concerns.append(.opaque("swift runs \(first) as a script"))
            return
        case nil:
            if args.contains(where: { $0 == "--version" || $0 == "-version" || $0 == "--help" }) { return }
            result.concerns.append(.opaque("swift with no subcommand starts a REPL or reads code from stdin"))
            return
        default:
            triggers = all
        }
        if args.contains("--disable-sandbox") {
            result.concerns.append(.trustBypass("--disable-sandbox turns off SwiftPM's manifest/plugin sandbox"))
        }
        result.invocations.append(Invocation(program: "swift", arguments: args, directory: directory, triggers: triggers))
    }

    private static func classifyXcodebuild(_ args: [String], directory: String, into result: inout ClassifiedCommand) {
        var triggers: Set<Trigger>
        if args.contains(where: { ["-version", "-showsdks", "-help", "-usage", "-license", "-checkFirstLaunchStatus"].contains($0) }) {
            triggers = []
        } else if args.contains(where: { ["-resolvePackageDependencies", "-list", "-showBuildSettings", "-showdestinations"].contains($0) }) {
            triggers = [.manifestEvaluation, .packageResolution]
        } else {
            triggers = [.manifestEvaluation, .packageResolution, .swiftPMBuild, .xcodeBuild]
        }
        for flag in ["-skipPackagePluginValidation", "-skipMacroValidation"] where args.contains(flag) {
            result.concerns.append(.trustBypass("\(flag) disables Xcode's own trust prompt for package plugins/macros"))
        }
        if args.contains(where: { $0.hasPrefix("-IDEPackageSupportDisableManifestSandbox") }) {
            result.concerns.append(.trustBypass("disables the package manifest sandbox"))
        }
        result.invocations.append(Invocation(program: "xcodebuild", arguments: args, directory: directory, triggers: triggers))
    }
}
