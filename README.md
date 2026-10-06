# RepoAdmission

**In an iOS repository, "just build it" is arbitrary code execution in at least five places — and a coding agent runs `git status` before it has read a single file.**

[![CI](https://github.com/rajatslakhina/repo-admission-gate-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/rajatslakhina/repo-admission-gate-kit/actions/workflows/ci.yml)
![Swift 6](https://img.shields.io/badge/Swift-6.0%2B-orange)
![Platforms](https://img.shields.io/badge/platforms-iOS%2017%20%7C%20macOS%2014%20%7C%20Linux-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

RepoAdmission is an **admission gate for untrusted repositories**, built to sit in front of a coding agent as a Claude Code `PreToolUse` hook. It inventories every place a cloned iOS repository can make your machine run its code, scores each one against a declarative, content-addressed policy, and decides each `git` / `swift` / `xcodebuild` tool call **before it runs**: allow, deny, or ask — with approvals bound to a SHA-256 of what was approved, and every decision in a hash-chained provenance log.

> Demo app: **[repo-admission-gate-kit-demo](https://github.com/rajatslakhina/repo-admission-gate-kit-demo)** — a separate Xcode project that consumes this package as a remote dependency (`upToNextMajorVersion` from 2.0.0, locked by a committed `Package.resolved`) and lets you sanitize, approve, and then watch an upstream edit void the approval.

---

## Why this matters

In September 2026, researchers disclosed eight Git configuration flaws that let a *received repository* run commands through seven AI coding agents — several still unpatched at publication ([The Hacker News](https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html)). That is the general case. iOS repositories are worse, because the Apple toolchain executes repository-controlled content in more places than most:

| Family | What runs | Fired by |
|---|---|---|
| **Git config** | in `config` and `config.worktree` of every git dir in the tree: `core.fsmonitor`, `core.pager`, `diff.*.textconv`, `filter.*.smudge`, `credential.helper`, `alias.x = !…`, `protocol.ext.allow`, `include.path`… | `git status`, `git diff`, `git checkout`, `git fetch`… |
| **Git hooks** | `.git/hooks/*` (and the hooks of an in-tree gitdir a `.git` *file* points at, or its `commondir`), or any tracked directory `core.hooksPath` points at | commit, checkout, push |
| **Git attributes & submodules** | `.gitattributes` wiring files to filter/diff/merge drivers; `ext::` submodule URLs | checkout, diff, `submodule update` |
| **SwiftPM** | `Package.swift` *is* Swift (sandboxed on macOS, **not on Linux**); build-tool & command plugins; macros; `unsafeFlags`; binary targets; every remote or registry package in the resolved graph | `swift build`, `swift package …`, `xcodebuild` |
| **Xcode project** | Run Script phases, custom build rules, legacy (external-build-tool) targets, scheme pre/post actions, build settings that swap the toolchain (`CC`, `LD`, `SWIFT_EXEC`…) or load compiler plugins (`OTHER_SWIFT_FLAGS = -load-plugin-executable …`) in `project.pbxproj` and `.xcconfig` | `xcodebuild` |

An agent's first move in a fresh checkout — `git status`, then `swift build` — fires most of that table. The control that matters is the one that runs *before* that move, on the machine that owns the credentials. That is a platform decision, not a per-repo one, which is why it is a library and a policy file rather than advice.

## What it does, in one flow

```
Bash tool call ──► CommandClassifier ──► triggers {gitIndexRead, swiftPMBuild, …} + concerns
                                              │
repo at each invocation's directory ──► RepoScanner (5 family scanners) ──► Inventory (ExecutionVectors)
                                              │
                         AdmissionPolicy ──► Assessment (allow / requireApproval / deny per vector)
                                              │
     fired = vectors whose `firedBy` ∩ command triggers ≠ ∅
                                              │
   injection? deny ─ fired deny? deny ─ fired needs approval & approval ≠ current surface? deny|ask
                       ─ opaque command? ask ─ otherwise allow (= print nothing)
                                              │
                                   ProvenanceLog (hash-chained)
```

## Design decisions (and what was rejected)

**1. Gate the operation, not the repository.** Each vector declares which agent actions fire it (`Trigger`), and the classifier maps each shell command onto the same vocabulary. A repo with a poisoned `.gitmodules` blocks `git submodule update`, not `ls` or `git log`. *Rejected:* quarantining the whole repo until it is clean. It is simpler, and it is how a security tool gets turned off by the team it is meant to protect: on any real codebase it would block everything, all day.

**2. Approval binds to content, never to a label.** `Assessment.approvalSurface` is a SHA-256 over every approval-requiring vector's identity *and content*. Edit one byte of an approved script phase, add a hook, move a package pin, and the surface changes — the stored approval silently stops matching and the next gated call is refused with *"The previous approval no longer matches"*. Unrelated edits (sources, README) do not disturb it. *Rejected:* approving a repo by path or name ("trust this folder"), which is exactly how "approve, then `git pull` brings a new Run Script phase, then `xcodebuild`" gets through. The test suite proves this binding matters by injecting a label-only surface function and showing the gate is then fooled (`testLabelBoundApprovalWouldMissTheUpstreamEdit`).

**3. Rescan on every gated call; never cache an assessment.** A cache *is* the time-of-check/time-of-use window. Scanning only reads control files (`.git/config`, hooks, attributes, manifests, lockfiles, `project.pbxproj`, schemes), so the cost is one directory walk plus a handful of small reads. *Accepted cost:* that walk on every `git`/`swift`/`xcodebuild` call. It is bounded by `ScanLimits` (entry ceiling, per-file byte ceiling, skipped `.git/objects`, `.build`, `DerivedData`). I have not benchmarked it on a large monorepo, so I make no latency claim. The hook scans from the **repository root**, found the way git finds it (walk up to the nearest `.git`): `cd Sources && git status` runs the root's fsmonitor, so scanning only `Sources/` would be scanning the wrong tree.

**4. Allow-lists are content-addressed.** Script phases, build rules, legacy targets, scheme actions and hooks are allow-listed by SHA-256; packages by identity **and** git revision. *Rejected:* allow-listing macro packages by name or by semver range — a name says nothing about what the next resolve fetches.

**5. Every package in the resolved graph is a vector, including transitive pins.** Whether a package vends a macro or plugin is unknowable until it is checked out, and checking it out *is* resolution (which evaluates its manifest). So the scanner unions packages declared in `Package.swift`, packages declared in `project.pbxproj`, and every pin in every `Package.resolved` in the tree. Two lockfiles that disagree on a revision leave the package **unpinned** — trust neither. *Rejected:* an allow-list over direct dependencies only, which is a list of the packages you remembered.

**6. Sanitization never touches a tracked file.** `SanitizationPlan` removes config lines (including `\`-continuations) and deletes `.git/hooks/*` — local metadata no diff or PR will ever show — so the agent's working tree stays byte-identical and its eventual diff contains only its own work. Attribute drivers are neutralised by removing the config that defines them; hooks in a tracked `core.hooksPath` directory by removing the `hooksPath`. Plans carry a baseline digest per file and refuse to apply if anything changed since planning. *Accepted cost:* tracked vectors (script phases, plugins, a poisoned `.gitmodules`) cannot be sanitized; they need approval or a human edit.

**7. `deny` is not approvable.** Approval clears `requireApproval` findings only. A `deny` keeps blocking the operations that fire it, approval or not — approving the demo's repository admits `swift build` but never `git submodule update`.

**8. The hook can only subtract permission.** For an allowed command `ClaudeCodeHook.respond` prints **nothing**, so Claude Code's own permission rules still run. Emitting `"permissionDecision": "allow"` would skip them, turning a security gate into a way around the user's settings. A mutation test enforces this.

**9. Fail closed, everywhere it is ambiguous.** An unreadable, oversized, symlinked or unparseable control file becomes an `unscannableControlFile` finding fired by *every* trigger. A command the classifier cannot see through — `$(…)`, backticks, a variable in program position, `eval`, `./scripts/x.sh`, `pod install` (Ruby), `make`, nesting deeper than 3 — is an `ask`, never an `allow`. An unknown git subcommand fires every git trigger (it may be an alias). A policy file with no rule for a class falls back to `requireApproval`, so vector classes added later fail closed under an old policy.

**10. Real parsers, not regexes, but no SwiftSyntax.** Git config follows git's own grammar (case-insensitive sections, `[a "b"]` and legacy `[a.b]` headers, a key on its header line, quotes, escapes, comments, continuations). `project.pbxproj` goes through a linear OpenStep-plist parser with a nesting cap (a file of 100 000 `(` throws `tooDeep` instead of overflowing the stack). `Package.swift` goes through a Swift *lexer* that strips comments (nested `/* */` included) and lifts out string literals (raw, multi-line, interpolated), so neither a commented-out `.plugin(` nor `"Process("` in a string is reported; it also lexes regex literals, strips identifier backticks and tolerates `.plugin (`. Every text scanner works on **Unicode scalars after CRLF→LF and BOM normalisation**: Swift's `Character` treats `"\r\n"` and a quote followed by a combining mark as single graphemes, and the first review of this code showed both hiding a `.plugin(`/`core.fsmonitor` from a grapheme-based scanner while SwiftPM and git still ran them. *Rejected:* SwiftSyntax — exact, but a large remote dependency whose own build takes minutes, and a gate that must run before any build cannot depend on one.

**11. Zero dependencies, including for SHA-256.** CryptoKit does not exist on Linux, and swift-crypto is a remote package — exactly what this library asks you to justify. SHA-256 is ~60 lines, checked against the NIST vectors. This package's own manifest is scanned by its own test suite (`testThisPackagesOwnManifestHasNoExecutionVectors`) and must contain nothing but the baseline manifest-evaluation vector.

**12. One actor, no suspension points inside a decision.** `AdmissionGate` is an actor so concurrent hook requests in one process serialise on the approval store and log, and none of its methods contain an `await` — scanning, assessment and the store are synchronous — so no other call can interleave mid-decision. A concurrency test fires 60 decisions, an approval, then 60 more, all concurrently within each burst, and checks that every decision logged before the approval is a deny, every one after is an allow, and the chain verifies.

## The red-team fixture

`RedTeamFixture.repo` is an in-memory repository that plants **40 execution vectors across all five families** — including evasions a naive scanner misses (`.plugin (name:…)` with a space before the paren, a `.package(id:)` registry dependency, a bare regex `/"/` whose lone quote would swallow a `FileManager` call on the same line, a compiler-plugin flag in a build configuration, `SWIFT_EXEC` in an `.xcconfig`) — and a set of decoys that must *not* be reported: a commented-out `.plugin(`, a nested block comment containing `.macro(`, a string containing `Process(` and `.plugin(`, `10 / 2` (division, not a regex), a `.sample` hook, a non-shell alias, a pbxproj comment mentioning `PBXShellScriptBuildPhase`, ordinary `SWIFT_VERSION`/`-warnings-as-errors` settings, a `.plugin(` inside a non-manifest Swift file, and the standard `CompilerPluginSupport` import. Every payload would only `touch /tmp/redteam-<vector>`, and none is ever executed: the fixture is only scanned.

`RedTeamFixture.audit(_:)` scores an inventory for **recall** (planted vectors missed) and **precision** (decoys reported). The tests require a perfect audit — and then prove the audit can fail: removing *any one* of the five family scanners fails it, and adding an over-reporting scanner fails the precision half. The same fixture is written to a real temporary directory and scanned through `DirectoryRepo`, which must produce an identical inventory.

## Usage

```swift
.package(url: "https://github.com/rajatslakhina/repo-admission-gate-kit.git", from: "2.0.0")
```

### As a Claude Code `PreToolUse` hook

The library deliberately ships no executable. Wrap it in your own tooling package:

```swift
// main.swift in your own tooling package's executable target
import Foundation
import RepoAdmission

let home = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".config/repo-admission")
let policy = (try? JSONDecoder().decode(AdmissionPolicy.self,
                                        from: Data(contentsOf: home.appendingPathComponent("policy.json")))) ?? .strict
let logURL = home.appendingPathComponent("provenance.json")
let gate = AdmissionGate(policy: policy,
                         store: JSONFileAdmissionStore(url: home.appendingPathComponent("approvals.json")),
                         log: try? JSONDecoder().decode(ProvenanceLog.self, from: Data(contentsOf: logURL)))
let stdin = FileHandle.standardInput.readDataToEndOfFile()
if let output = await ClaudeCodeHook.respond(to: stdin, gate: gate) {
    FileHandle.standardOutput.write(output)   // deny/ask JSON; nothing at all for allow
}
try? JSONEncoder().encode(await gate.log).write(to: logURL, options: .atomic)  // one chain across calls
```

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash",
  "hooks": [ { "type": "command", "command": "repo-admission-hook" } ] } ] } }
```

Keep `policy.json` and `approvals.json` **outside** every repository they describe — a repository must not be able to ship its own approval.

### Programmatically

```swift
func admit(_ checkoutURL: URL) async throws -> GateDecision {
    let gate = AdmissionGate(policy: .strict)              // or .paranoid on Linux / CI
    var repo = DirectoryRepo(root: checkoutURL)

    let assessment = try await gate.assess(repo: checkoutURL.path, repo)
    try await gate.sanitize(repo: checkoutURL.path, &repo)  // git metadata only

    // A human reviews `assessment.pendingApproval`, then approves exactly what they saw:
    let surface = await gate.surface(of: try await gate.assess(repo: checkoutURL.path, repo))
    try await gate.approve(repo: checkoutURL.path, repo, expected: surface, approver: "rajat")
    _ = assessment

    return await gate.decide("xcodebuild -scheme App build",
                             repoKey: { _ in checkoutURL.path },
                             repoAt: { _ in DirectoryRepo(root: checkoutURL) })
}
```

`approve` re-scans and throws `staleApproval` if the tree changed between showing the surface and approving it — nobody can approve something they did not look at.

## Policy

`AdmissionPolicy.strict` (default): git-level command execution, includes, `gitdir` redirects, driver-wired attributes and submodule injection are **deny**; of those, git config commands, includes and the attribute drivers they define are sanitizable, while gitdir/commondir redirects and submodule injection (tracked in `.gitmodules`) are not. Hooks, `core.hooksPath`, plugins, macros, `unsafeFlags`, binary targets, remote packages, out-of-tree path dependencies, script phases, build rules, legacy targets, scheme actions, toolchain/plugin build settings, version-specific manifests and manifest side effects (`Process`, `FileManager`, `URLSession`, `ProcessInfo`, `getenv`, non-standard imports…) **require approval**. Manifest evaluation and latent attribute drivers are **allowed**.

`AdmissionPolicy.paranoid`: for Linux hosts and CI runners where SwiftPM evaluates manifests with no sandbox — manifest evaluation and latent drivers require approval, and an unscannable control file is a deny. Policies are `Codable` into readable JSON (`{"rules": {"scriptPhase": "requireApproval", …}, "allowedDigests": […], "allowedPackages": [{"identity": …, "revision": …}]}`).

## What it does not do

* **It is not a sandbox.** It decides whether to *start* an operation; it does not contain one. Pair it with OS-level isolation for anything you would not run on your own machine.
* **The shell classifier is not a shell.** It handles quotes, escapes and line continuations, `&& || ; | &`, subshells (a `cd` inside `( … )` does not leak out), reserved words (`if … then`, `!`, `{ … }`, `for … do`, `coproc`), redirections, env prefixes and `export`/`declare -x`, `cd`/`pushd` (and treats `popd`, `cd -` and `~` paths as unknowable), wrappers (`env` including `env -C`, `sudo`, `nice`, `timeout`, `stdbuf`, `flock`, `setsid`, `exec -a`, `xcrun`…), `sh -c [--]` nesting, `xargs` (which appends unseen arguments, so a bare `xargs git` fails closed), `git-<sub>` and `swift-build`/`swift-package` helper binaries, `swift --package-path` and `xcodebuild -project/-workspace` directories, `gh pr checkout`; and it refuses (`ask`) what it cannot see through — `$(…)`/backticks inside or outside double quotes, process substitution `<(…)`, brace expansion or globs in program position, `env -S`, `flock -c`, unterminated quotes, `find -exec`. Heredoc bodies are tokenised as commands (conservative: may over-trigger). A program it has never heard of, not given as a path into the repo, is treated as not running repository code — that boundary is the honest limit of a classifier, which is why this is an admission gate and not a sandbox.
* **The manifest scan is lexical.** It tolerates whitespace before the paren, lexes strings, raw strings, interpolation and regex literals, and knows `.package(id:)`. It does **not** evaluate Swift: a manifest that reaches a target constructor indirectly (`let make = Target.plugin; make(…)`) is not named. That is exactly why evaluating the manifest is itself a vector, and why `.paranoid` makes it require approval — use it wherever that gap matters.
* **Not covered yet:** Xcode 27.2's JSON `project.xcproj` ([background](https://fatbobman.com/en/posts/from-pbxproj-to-xcproj/), [XcodeProj #1177](https://github.com/tuist/XcodeProj/pull/1177)) is not parsed — it is reported as an `unscannableControlFile` (fail closed), not skipped. `#include` lines in `.xcconfig` files are not followed. Tuist/XcodeGen manifests and `.envrc`/`mise` files are not scanned (their *commands* are classified as opaque). A submodule's own metadata (`.git/modules/*`) is not scanned from the superproject; inside the submodule its `.git` file points outside the scanned tree, which is reported as a `gitDirRedirect` (deny). Git's global and system config are the host's, deliberately out of scope.
* **Approvals are per-machine** (`AdmissionStore`), and `JSONFileAdmissionStore` is last-writer-wins across processes (writes are atomic, so never corrupt). The same is true of the hook snippet's `provenance.json`: Claude Code can run Bash hooks for parallel tool calls concurrently, and two processes that load-append-write the same log fork the chain (the later write wins, and `verify()` on the survivor still passes — the lost branch is simply gone). If you need every decision, wrap the load/append/write in a file lock (`flock`) or send entries to an append-only sink.
* **The provenance log is tamper-evident, not tamper-proof.** A partial edit breaks verification at that entry; a consistent rewrite of the whole chain does not. Anchor `log.head` somewhere the agent cannot write (a CI artifact, a commit trailer) to turn that into proof. In a hook each invocation is a new process, so the snippet above persists the `Codable` log and hands it to the next gate (`AdmissionGate(log:)`), which continues the same chain.

## Verification

* **Build:** `swift build -Xswiftc -warnings-as-errors` from a clean `.build` — 0 warnings — on Swift 6.1.2 (Linux x86_64) in the sandbox where this was written; enforced the same way in CI.
* **Tests:** `swift test` — **89 tests, 0 failures** locally on Swift 6.1.2 / Linux. Includes the NIST SHA-256 vectors; git-config grammar an attacker could use to hide a key, in LF, CRLF and BOM-prefixed files; hostile/truncated input for every parser (no traps, and fail-closed results asserted); shell forms that hide a git or SwiftPM call (`if`, `!`, `{ }`, `for … do`, `coproc`, `timeout`, `flock`, `xargs`, line continuations, `git-status`, `swift-build`, process and quoted command substitution, brace expansion, subshell `cd`, `env -C`, `~`, `popd`); inline and environment injection spellings; in-tree gitdirs/`config.worktree`/`commondir`; manifest evasions (CRLF, combining marks, backticks, spaced calls, regex literals, registry packages); pbxproj conditional keys and `$(VAR)` indirection; the red-team recall/precision audit and its two "audit can fail" tests; a real-filesystem scan; a subdirectory hook call scanned at the repository root; header-line and CRLF sanitizing; the full sanitize → approve → upstream-edit → re-quarantine flow; the burst/approve/burst linearisability test; and the demo's view-model flow under the demo's own policy (including overlapping button taps).
* **Mutation check:** [`Scripts/mutation-check.sh`](Scripts/mutation-check.sh) first verifies the unmutated tree builds and passes, then applies **17** deliberate breakages — one per property this README claims (SHA-256 round function, content-bound approval, deny-not-approvable, stale-plan refusal, inline-injection detection, hook-never-emits-allow, provenance content check, lexer comment stripping, `fsmonitor = true` handling, unscannable-file reporting, header-line sanitizing, shell reserved words, in-tree gitdir scanning, repository-root resolution in the hook, serialised console actions, CRLF/BOM normalisation, backtick identifiers) — compiles each mutant (touching the restored file so no mutant object survives into the next run), and requires the named suite to **fail**. Local result: **17 of 17 mutants compiled and all 17 were caught**, with the baseline passing before and after.
* **CI:** [Actions](https://github.com/rajatslakhina/repo-admission-gate-kit/actions/workflows/ci.yml) is configured to run three jobs on every push (results are on the Actions page, not asserted here): Linux (`swift:6.1-noble`: clean build with warnings-as-errors, then tests), macOS (`macos-15`: the same), and an iOS Simulator compile of the SwiftUI module for `generic/platform=iOS Simulator`.
* **Simulator:** Whether the demo app was actually launched on an iOS Simulator — and the screenshots, if it was — is recorded in the [demo repository](https://github.com/rajatslakhina/repo-admission-gate-kit-demo#verification). This library repository contains no app target of any kind.

## Layout

```
Sources/RepoAdmission/
  Digest.swift               SHA-256, Digest, saturating helpers
  RepoFileSource.swift       RepoFileSource / WritableRepo, InMemoryRepo, DirectoryRepo, ScanLimits
  ExecutionVector.swift      Trigger, VectorFamily, VectorClass, ExecutionVector, Inventory
  RepoScanner.swift          ScanContext (fail-closed integrity findings), VectorScanner, RepoScanner
  GitScanners.swift          git-config parser + exec-key table, config / hooks / attributes+submodule scanners
  PackageScanner.swift       Swift lexer, manifest scanner, Package.resolved v1–v3
  XcodeProjectScanner.swift  OpenStep plist parser, pbxproj + scheme scanner
  AdmissionPolicy.swift      Disposition, AdmissionPolicy (.strict / .paranoid), Assessment, approval surface
  CommandClassifier.swift    shell tokeniser → invocations, triggers, concerns
  Sanitizer.swift            SanitizationPlan (.git/-only, baseline-checked)
  AdmissionGate.swift        the actor; ApprovalRecord, AdmissionStore (memory / JSON file)
  ProvenanceLog.swift        bounded, hash-chained, cross-platform-canonical log
  ClaudeCodeHook.swift       PreToolUse adapter
  RedTeamFixture.swift       40 planted vectors + decoys, recall/precision audit
Sources/RepoAdmissionUI/     AdmissionConsoleModel (Linux-tested) + SwiftUI console
```

## License

MIT
