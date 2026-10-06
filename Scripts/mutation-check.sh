#!/usr/bin/env bash
# Mutation check: each mutation deliberately breaks one property the README
# claims, and the named test suite MUST fail against it. A suite that still
# passes against a broken implementation is reporting coverage it does not have.
#
# Usage: Scripts/mutation-check.sh        (from the package root; restores every file)
set -uo pipefail
cd "$(dirname "$0")/.."

caught=0; missed=0
mutate() {  # file, from, to, test-filter, description
  local file="$1" from="$2" to="$3" filter="$4" what="$5"
  cp "$file" "$file.orig"
  python3 - "$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if text.count(old) != 1:
    sys.exit(f"mutation anchor not found exactly once in {path}: {old!r}")
open(path, "w").write(text.replace(old, new))
PY
  if [ $? -ne 0 ]; then mv "$file.orig" "$file"; echo "ERROR  $what (anchor missing)"; missed=$((missed+1)); return; fi
  # A mutant that does not compile would "fail" the tests for the wrong
  # reason, so compile first and count that as an error, not a catch.
  if ! swift build --build-tests >/dev/null 2>&1; then
    echo "ERROR  $what (mutant did not compile)"; missed=$((missed+1))
  elif swift test --skip-build --filter "$filter" >/dev/null 2>&1; then
    echo "MISSED $what — $filter still passes"; missed=$((missed+1))
  else
    echo "caught $what"; caught=$((caught+1))
  fi
  mv "$file.orig" "$file"
  # `mv` restores the ORIGINAL mtime, which is older than the mutant's object
  # file — an incremental build would then keep linking the mutant into every
  # later run. Touch it so the restored source is always recompiled.
  touch "$file"
}

# Baseline: the unmutated tree must build and pass, or every "caught" below
# would be caught for the wrong reason.
if ! swift build --build-tests >/dev/null 2>&1 || ! swift test --skip-build >/dev/null 2>&1; then
  echo "baseline build/test failed on the unmutated tree — fix that first"; exit 2
fi

S=Sources/RepoAdmission
mutate $S/Digest.swift 'let s1 = rotr(e, 6)' 'let s1 = rotr(e, 7)' DigestTests \
  "SHA-256 round function off by one rotation"
mutate $S/AdmissionPolicy.swift 'pendingApproval.map { ($0.vector.id, $0.vector.digest) }' 'pendingApproval.map { ($0.vector.id, Digest.of("")) }' AdmissionGateTests \
  "approval bound to vector labels instead of content"
mutate $S/AdmissionGate.swift 'let denied = fired.filter { $0.disposition == .deny }' 'let denied = fired.filter { _ in false }' AdmissionGateTests \
  "deny findings treated as approvable"
mutate $S/Sanitizer.swift 'guard Digest.of(bytes: bytes) == expected else' 'guard true else' SanitizerTests \
  "sanitizer applies a stale plan"
mutate $S/CommandClassifier.swift 'if GitExecKeys.classify(entry) != nil {' 'if false {' CommandClassifierTests \
  "inline git -c injection not detected"
mutate $S/ClaudeCodeHook.swift 'case .allow: return nil' 'case .allow: return render(.allow, decision.reason)' ClaudeCodeHookTests \
  "hook emits permissionDecision allow (bypasses the user's permission rules)"
mutate $S/ProvenanceLog.swift 'if recomputed != entry.hash {' 'if false {' ProvenanceLogTests \
  "provenance verify ignores entry content"
mutate $S/PackageScanner.swift 'if c == "/", next == "/" {' 'if false, next == "/" {' RedTeamFixtureTests \
  "manifest lexer stops stripping line comments (decoy plugin reported)"
mutate $S/GitScanners.swift 'let isCommandValue = entry.value != nil && !booleanLiterals.contains(value.lowercased())' 'let isCommandValue = entry.value != nil' GitConfigParserTests \
  "core.fsmonitor = true misread as a command"
mutate $S/RepoScanner.swift 'vectors.append(contentsOf: context.problems)' '_ = context.problems' ScanIntegrityTests \
  "unscannable control files silently skipped"

mutate $S/Sanitizer.swift 'drop.remove(lines.lowerBound)' '_ = drop' SanitizerTests \
  "sanitizer deletes a header line that also holds the key"
mutate $S/CommandClassifier.swift 'while let (word, dynamic) = words.first, !dynamic, reservedWords.contains(word) {' 'while let (word, dynamic) = words.first, !dynamic, false, reservedWords.contains(word) {' CommandClassifierTests \
  "shell reserved words (if/!/{/do) hide the git call"
mutate $S/RepoScanner.swift '                bases.append(normalized)' '                _ = normalized' GitScannerTests \
  "in-tree gitdir (.git file) not scanned"
mutate $S/ClaudeCodeHook.swift 'return repositoryRoot(containing: start.standardizedFileURL)' 'return start.standardizedFileURL' ClaudeCodeHookTests \
  "hook scans the subdirectory instead of the repository root"
mutate Sources/RepoAdmissionUI/AdmissionConsoleModel.swift 'guard !isBusy else { return false }' 'guard true else { return false }' AdmissionConsoleModelTests \
  "console model lets overlapping actions interleave"

mutate $S/RepoScanner.swift 'bytes(path).map(Self.normalizedText)' 'bytes(path).map { String(decoding: $0, as: UTF8.self) }' EncodingHardeningTests \
  "CRLF/BOM not normalised before line-based scanning"
mutate $S/PackageScanner.swift 'if c == "`" {' 'if false, c == "`" {' EncodingHardeningTests \
  "backtick-escaped identifiers hide manifest calls"

echo "mutations caught: $caught, missed: $missed"
# Leave the tree verified clean again.
swift build --build-tests >/dev/null 2>&1 && swift test --skip-build >/dev/null 2>&1 || { echo "post-run baseline failed"; exit 3; }
[ "$missed" -eq 0 ]
