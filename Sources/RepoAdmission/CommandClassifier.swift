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
        case open    // "(" — a subshell: `cd` inside it does not leak out
        case close   // ")"
        case redirect
    }

    static func tokenize(_ command: String, concerns: inout [Concern]) -> [Token] {
        var tokens: [Token] = []
        var word = ""
        var inWord = false
        var dynamic = false
        // Per Unicode scalar: "\r\n" or a combining mark must not fuse with a
        // quote or separator and change where a word ends.
        var chars = command.unicodeScalars.map(Character.init)[...]

        func flush() {
            if inWord { tokens.append(.word(word, dynamic: dynamic)) }
            word = ""; inWord = false; dynamic = false
        }

        while let c = chars.first {
            chars = chars.dropFirst()
            switch c {
            case " ", "\t":
                flush()
            case "(", ")":
                flush()
                tokens.append(c == "(" ? .open : .close)
            case "\n", ";", "&", "|":
                flush()
                if c == "&", chars.first == ">" { tokens.append(.redirect); chars = chars.dropFirst(); continue }
                tokens.append(.separator)
                // Collapse &&, ||
                if (c == "&" || c == "|"), chars.first == c { chars = chars.dropFirst() }
            case ">", "<":
                // A bare fd number before the operator ("2>") belongs to it.
                if inWord, !word.isEmpty, word.allSatisfy(\.isNumber), !dynamic { word = ""; inWord = false }
                flush()
                if chars.first == "(" {
                    // Process substitution `<(cmd)` / `>(cmd)`: the inner command
                    // runs. Classify it as a subshell, and refuse to vouch for it.
                    concerns.append(.opaque("process substitution runs a command inside an argument"))
                    tokens.append(.separator)
                    continue
                }
                while let n = chars.first, n == ">" || n == "<" || n == "&" || n == "|" { chars = chars.dropFirst() }
                tokens.append(.redirect)
            case "#" where !inWord:
                // Comment to end of line.
                while let n = chars.first, n != "\n" { chars = chars.dropFirst() }
            case "'":
                inWord = true
                while let n = chars.first, n != "'" { word.append(n); chars = chars.dropFirst() }
                if chars.isEmpty { concerns.append(.opaque("unterminated quote")) }
                chars = chars.dropFirst()
            case "\"":
                inWord = true
                while let n = chars.first, n != "\"" {
                    chars = chars.dropFirst()
                    if n == "\\", let escaped = chars.first, "\"\\$`\n".contains(escaped) {
                        word.append(escaped); chars = chars.dropFirst(); continue
                    }
                    if n == "$" || n == "`" { dynamic = true }
                    if n == "`" || (n == "$" && chars.first == "(") {
                        concerns.append(.opaque("command substitution inside double quotes — the command it runs is only known at run time"))
                    }
                    word.append(n)
                }
                if chars.isEmpty { concerns.append(.opaque("unterminated quote")) }
                chars = chars.dropFirst()
            case "\\":
                if chars.first == "\n" {
                    // Line continuation: `gi\<newline>t` is `git`.
                    chars = chars.dropFirst()
                    continue
                }
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
        var cwdStack: [String?] = []   // saved at "(", restored at ")"
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
                skipNext = false
            case .open:
                finishSegment()
                skipNext = false
                cwdStack.append(cwd)
            case .close:
                finishSegment()
                skipNext = false
                if let saved = cwdStack.popLast() { cwd = saved }
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
        "GIT_TEMPLATE_DIR", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_CONFIG",
        "PAGER", "EDITOR", "VISUAL",
    ]

    static let wrappers: Set<String> = ["env", "sudo", "doas", "time", "nice", "nohup", "command", "builtin", "exec", "xcrun",
                                        "caffeinate", "arch", "timeout", "gtimeout", "stdbuf", "watch", "unbuffer",
                                        "flock", "setsid", "chronic", "ionice", "taskpolicy"]
    /// Per-wrapper options that consume the next word.
    static let wrapperOptionsWithValue: [String: Set<String>] = [
        "env": ["-u", "--unset", "-C", "--chdir"],
        "sudo": ["-u", "-g", "-C", "-h", "-p", "-U", "-D"],
        "doas": ["-u", "-C"],
        "nice": ["-n", "--adjustment"],
        "xcrun": ["--sdk", "-sdk", "--toolchain", "-toolchain"],
        "timeout": ["-s", "--signal", "-k", "--kill-after"],
        "gtimeout": ["-s", "--signal", "-k", "--kill-after"],
        "stdbuf": ["-i", "-o", "-e"],
        "watch": ["-n", "--interval", "-d"],
        "caffeinate": ["-t", "-w"],
        "exec": ["-a"],
        "flock": ["-w", "--timeout", "-E", "--conflict-exit-code"],
        "ionice": ["-c", "-n", "-p"],
        "taskpolicy": ["-c", "-d", "-g", "-b"],
    ]
    /// Shell reserved words that can precede a command in a simple command list.
    static let reservedWords: Set<String> = ["if", "then", "elif", "else", "fi", "while", "until", "do", "done",
                                             "for", "case", "esac", "!", "{", "}", "[[", "]]", "select", "in", "coproc"]
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
        "script": "script runs a command line it is given",
        "source": "source runs a file as shell code",
        ".": "`.` runs a file as shell code",
    ]

    private static func classifySegment(_ rawSegment: [(String, Bool)], cwd: inout String?, depth: Int,
                                        into result: inout ClassifiedCommand) {
        var words = rawSegment[...]
        var directoryOverride: String?   // set by `env -C DIR`; "~" means unknowable
        while let (word, dynamic) = words.first, !dynamic, reservedWords.contains(word) {
            words = words.dropFirst()
        }

        // Leading VAR=value assignments.
        while let (word, _) = words.first, let eq = word.firstIndex(of: "="),
              word[..<eq].allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" }), !word[..<eq].isEmpty {
            checkEnvAssignment(String(word[..<eq]), value: String(word[word.index(after: eq)...]), into: &result)
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
                if wrapper == "env", option == "-S" || option.hasPrefix("--split-string") || (option.hasPrefix("-S") && option.count > 2) {
                    result.concerns.append(.opaque("env -S re-splits a string into a command line"))
                    return
                }
                if wrapper == "env", let eq = option.firstIndex(of: "="), !option.hasPrefix("-") {
                    checkEnvAssignment(String(option[..<eq]), value: String(option[option.index(after: eq)...]), into: &result)
                }
                if wrapper == "env", option == "-C" || option == "--chdir" || option.hasPrefix("--chdir=") {
                    // `env -C DIR cmd` runs cmd in DIR: that is the tree to scan.
                    let value = option.hasPrefix("--chdir=") ? String(option.dropFirst("--chdir=".count)) : words.dropFirst().first?.0
                    if let value, let base = directoryOverride ?? cwd { directoryOverride = resolve(base, value) ?? "~" } else { directoryOverride = "~" }
                }
                if wrapper == "flock", option == "-c" || option == "--command" {
                    result.concerns.append(.opaque("flock -c runs a command string"))
                    return
                }
                words = words.dropFirst()
                if wrapperOptionsWithValue[wrapper]?.contains(option) == true { words = words.dropFirst() }
            }
            // `timeout [opts] DURATION cmd…`, `flock [opts] LOCKFILE cmd…`
            if ["timeout", "gtimeout", "flock"].contains(wrapper) { words = words.dropFirst() }
            if wrapper == "flock", let next = words.first?.0, next == "-c" || next == "--command" {
                result.concerns.append(.opaque("flock -c runs a command string"))
                return
            }
        }

        guard let (programWord, programDynamic) = words.first else { return }
        let arguments = words.dropFirst().map(\.0)
        if programDynamic {
            result.concerns.append(.opaque("program name is computed at run time: \(programWord)"))
            return
        }
        guard let directory = directoryOverride ?? cwd, directory != "~" else {
            result.concerns.append(.opaque("working directory became unknowable earlier in the command"))
            return
        }
        let program = PathText.lastComponent(programWord)

        // Brace expansion and globs in program position (`{git,status}`,
        // `/usr/bin/[g]it`) are expanded by the shell into a program the
        // classifier never sees spelled out. (`[` alone is the test builtin.)
        if program != "[", program != "[[", programWord.contains(where: { "{}*?[".contains($0) }) {
            result.concerns.append(.opaque("program name is produced by shell expansion: \(programWord)"))
            return
        }

        // A path to a program inside the tree is repository code.
        if programWord.contains("/"), !programWord.hasPrefix("/") {
            result.concerns.append(.opaque("runs a repository file directly: \(programWord)"))
            return
        }

        switch program {
        case "cd", "pushd":
            let target = words.dropFirst().first { !$0.0.hasPrefix("-") || $0.0 == "-" }
            if let target, !target.1, target.0 != "-" {
                cwd = resolve(directory, target.0)   // nil for `~…`
            } else {
                cwd = nil  // `cd` alone, `cd -`, or a computed target: outside anything we can name
            }
        case "popd":
            cwd = nil      // the directory stack is not modelled: unknowable
        case "export", "declare", "typeset", "local", "readonly":
            for argument in arguments {
                if let eq = argument.firstIndex(of: "=") {
                    checkEnvAssignment(String(argument[..<eq]), value: String(argument[argument.index(after: eq)...]), into: &result)
                }
            }
        case "git":
            classifyGit(arguments, directory: directory, into: &result)
        case let name where name.hasPrefix("git-"):
            // `/usr/lib/git-core/git-status` is `git status`.
            classifyGit([String(name.dropFirst(4))] + arguments, directory: directory, into: &result)
        case "swift":
            classifySwift(arguments, directory: directory, into: &result)
        case "swift-build", "swift-test", "swift-run", "swift-package":
            classifySwift([String(program.dropFirst("swift-".count))] + arguments, directory: directory, into: &result)
        case "xcodebuild":
            classifyXcodebuild(arguments, directory: directory, into: &result)
        case "swiftc":
            if arguments.contains(where: { $0.hasPrefix("-load-plugin") || $0.hasPrefix("-plugin-path") }) {
                result.concerns.append(.opaque("swiftc is loading compiler plugins named on the command line"))
            }
        case "xargs":
            var rest = arguments[...]
            while let option = rest.first, option.hasPrefix("-") {
                rest = rest.dropFirst()
                if ["-n", "-I", "-L", "-P", "-s", "-E", "-d", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file"].contains(option) {
                    rest = rest.dropFirst()
                }
            }
            if !rest.isEmpty {
                // xargs APPENDS words from stdin, so the command it runs has
                // arguments we cannot see: `echo status | xargs git` is `git
                // status`. The placeholder makes "no subcommand yet" read as an
                // unknown subcommand, which fails closed.
                let command = (rest + ["__xargs_input__"]).map(shellQuote).joined(separator: " ")
                classify(command, directory: directory, depth: depth + 1, into: &result)
            }
        case "gh":
            // `gh pr checkout` / `gh repo sync` run git checkout and fetch in this repo.
            let positional = arguments.filter { !$0.hasPrefix("-") }
            if positional.starts(with: ["pr", "checkout"]) || positional.starts(with: ["repo", "sync"]) {
                result.invocations.append(Invocation(program: "gh", arguments: arguments, directory: directory,
                                                     triggers: [.gitIndexRead, .gitCheckout, .gitCommit, .gitNetwork]))
            }
        case "find":
            if arguments.contains(where: { ["-exec", "-execdir", "-ok", "-okdir"].contains($0) }) {
                result.concerns.append(.opaque("find -exec runs a command per file"))
            }
        default:
            if shells.contains(program) {
                if let flag = arguments.firstIndex(where: { $0.hasPrefix("-") && $0.contains("c") && !$0.hasPrefix("--") }),
                   let script = arguments.dropFirst(flag + 1).first(where: { $0 != "--" }) {
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

    /// Values that make a pager/editor variable run nothing.
    static let inertCommandValues: Set<String> = ["", "cat", "true", ":", "/bin/cat", "/usr/bin/cat", "/usr/bin/true"]
    static let commandVariables: Set<String> = ["GIT_PAGER", "PAGER", "GIT_EDITOR", "EDITOR", "VISUAL", "GIT_SEQUENCE_EDITOR"]

    private static func checkEnvAssignment(_ name: String, value: String, into result: inout ClassifiedCommand) {
        // `PAGER=cat git log` is how agents avoid an interactive pager; it is
        // not an injection. Any other value for these runs that value.
        if commandVariables.contains(name), inertCommandValues.contains(value) { return }
        if gitEnvInjections.contains(name) || name.hasPrefix("GIT_CONFIG_KEY_") || name.hasPrefix("GIT_CONFIG_VALUE_") {
            result.concerns.append(.injection("sets \(name), which makes git run a command or read config this gate did not scan"))
        }
    }

    /// nil when the path depends on the user's home or another user (`~…`):
    /// the hook cannot name that tree, so the caller fails closed.
    static func resolve(_ base: String, _ path: String) -> String? {
        if path.hasPrefix("/") { return path }
        if path.hasPrefix("~") { return nil }
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
        // Plumbing that applies filters: `hash-object` runs the clean filter,
        // `cat-file --filters/--textconv` the smudge filter and textconv,
        // `archive` the smudge filter. `help` runs man/browser commands.
        table["hash-object"] = [.gitIndexRead, .gitCheckout]
        table["cat-file"] = [.gitContentRender, .gitCheckout]
        table["archive"] = [.gitNetwork, .gitCheckout, .gitContentRender]
        table["help"] = [.gitContentRender]
        table["instaweb"] = [.gitContentRender]
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
                guard let resolved = resolve(dir, value) else {
                    result.concerns.append(.opaque("git -C \(value) names a directory relative to a home directory"))
                    return
                }
                dir = resolved; index += 2; continue
            }
            if arg == "-c" || arg.hasPrefix("--config-env") {
                // `-c k=v`, `--config-env k=ENV` (value in the next word) or `--config-env=k=ENV`.
                let assignment = arg == "-c" || arg == "--config-env"
                    ? (args[safe: index + 1] ?? "")
                    : String(arg.drop(while: { $0 != "=" }).dropFirst())
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
            if (sub == "config" && args.contains(where: { $0 == "-e" || $0 == "--edit" || $0 == "edit" }))
                || (sub == "branch" && args.contains("--edit-description")) {
                triggers.insert(.gitCommit)   // opens core.editor
            }
            if sub == "config" {
                // `git config core.fsmonitor "<cmd>"` plants the vector this gate
                // exists to catch; an agent writing it is the same injection.
                // Skip options (and the values of `-f/--file/--blob/--type/…`),
                // and git 2.46's `set`/`add` verbs, to find `<key> <value>`.
                var positional: [String] = []
                var rest = args.drop(while: { $0 != "config" }).dropFirst()[...]
                while let word = rest.first {
                    rest = rest.dropFirst()
                    if word.hasPrefix("-") {
                        if ["-f", "--file", "--blob", "--type", "--default", "--comment", "--value"].contains(word) {
                            rest = rest.dropFirst()
                        }
                        continue
                    }
                    positional.append(word)
                }
                if let verb = positional.first, ["set", "add"].contains(verb) { positional.removeFirst() }
                if let key = positional.first, positional.count >= 2, let value = positional[safe: 1] {
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

    /// The value of `--name VALUE` or `--name=VALUE`.
    static func optionValue(_ name: String, in args: [String]) -> String? {
        for (index, arg) in args.enumerated() {
            if arg == name { return args[safe: index + 1] }
            if arg.hasPrefix(name + "=") { return String(arg.dropFirst(name.count + 1)) }
        }
        return nil
    }

    private static func classifySwift(_ args: [String], directory originalDirectory: String, into result: inout ClassifiedCommand) {
        var directory = originalDirectory
        if let packagePath = optionValue("--package-path", in: args) {
            guard let resolved = resolve(originalDirectory, packagePath) else {
                result.concerns.append(.opaque("--package-path \(packagePath) is relative to a home directory"))
                return
            }
            directory = resolved
        }
        var positional: [String] = []
        var index = 0
        while index < args.count {
            let arg = args[index]
            if ["--package-path", "--scratch-path", "-c", "--configuration", "--product", "--target", "--build-path",
                "--cache-path", "--config-path", "--security-path", "--swift-sdk", "--triple", "--jobs", "-j"].contains(arg) {
                index += 2
                continue
            }
            if !arg.hasPrefix("-") { positional.append(arg) }
            index += 1
        }
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

    private static func classifyXcodebuild(_ args: [String], directory originalDirectory: String, into result: inout ClassifiedCommand) {
        var directory = originalDirectory
        // `-project /x/App.xcodeproj` / `-workspace /x/App.xcworkspace` build a
        // tree that need not be the cwd: scan the directory that holds it.
        if let container = optionValue("-project", in: args) ?? optionValue("-workspace", in: args) {
            guard let resolved = resolve(originalDirectory, container) else {
                result.concerns.append(.opaque("xcodebuild container \(container) is relative to a home directory"))
                return
            }
            let parent = PathText.directory(resolved)
            directory = parent.isEmpty ? (resolved.hasPrefix("/") ? "/" : ".") : parent
        }
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
