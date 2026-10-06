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
}

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

echo "mutations caught: $caught, missed: $missed"
[ "$missed" -eq 0 ]
