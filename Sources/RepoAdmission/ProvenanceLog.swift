import Foundation

/// Final verdict for a tool call.
public enum Verdict: String, Codable, Sendable {
    case allow, ask, deny
}

/// Something the gate did that a reviewer may later need to reconstruct.
public enum ProvenanceEvent: Codable, Sendable, Equatable {
    case assessed(repo: String, inventory: Digest, surface: Digest, blocking: Int, pending: Int)
    case approved(repo: String, surface: Digest, approver: String)
    case approvalVoided(repo: String, approved: Digest, current: Digest)
    case revoked(repo: String)
    case sanitized(repo: String, actions: Int, remaining: Int)
    case decided(command: String, verdict: Verdict, reason: String)

    /// Deterministic text the chain hashes. Hand-written rather than
    /// `JSONEncoder` output, whose escaping differs between Foundation
    /// implementations — a log written on macOS must verify on Linux.
    var canonical: String {
        func esc(_ s: String) -> String { "\(s.utf8.count):\(s)" }
        switch self {
        case let .assessed(repo, inventory, surface, blocking, pending):
            return "assessed|\(esc(repo))|\(inventory.hex)|\(surface.hex)|\(blocking)|\(pending)"
        case let .approved(repo, surface, approver):
            return "approved|\(esc(repo))|\(surface.hex)|\(esc(approver))"
        case let .approvalVoided(repo, approved, current):
            return "voided|\(esc(repo))|\(approved.hex)|\(current.hex)"
        case let .revoked(repo):
            return "revoked|\(esc(repo))"
        case let .sanitized(repo, actions, remaining):
            return "sanitized|\(esc(repo))|\(actions)|\(remaining)"
        case let .decided(command, verdict, reason):
            return "decided|\(esc(command))|\(verdict.rawValue)|\(esc(reason))"
        }
    }
}

public struct ProvenanceEntry: Codable, Sendable, Equatable {
    public let sequence: UInt64
    public let timestampMilliseconds: Int64
    public let event: ProvenanceEvent
    public let previous: Digest
    public let hash: Digest

    static func link(sequence: UInt64, timestampMilliseconds: Int64, event: ProvenanceEvent, previous: Digest) -> Digest {
        .of("\(previous.hex)|\(sequence)|\(timestampMilliseconds)|\(event.canonical)")
    }
}

/// An append-only, hash-chained, bounded record of every assessment, approval
/// and decision.
///
/// Tamper-evident, not tamper-proof: anyone with write access can rewrite the
/// whole chain consistently. What it buys is that a *partial* edit — changing
/// one decision after the fact — breaks verification at that entry. Anchoring
/// the head hash somewhere the agent cannot write (a CI artifact, a commit
/// trailer) is what turns that into proof; this type gives you the head to anchor.
///
/// Bounded: past `capacity` the oldest entries are dropped and the dropped
/// tail's hash becomes the new `anchor`, so the retained window still verifies
/// and the truncation itself is visible (`droppedCount`).
public struct ProvenanceLog: Codable, Sendable, Equatable {
    public static let genesis = Digest.of("repo-admission/provenance/genesis/v1")

    public let capacity: Int
    public internal(set) var entries: [ProvenanceEntry] = []
    public private(set) var anchor: Digest = ProvenanceLog.genesis
    public private(set) var droppedCount: UInt64 = 0
    private var nextSequence: UInt64 = 0

    public init(capacity: Int = 1_000) {
        self.capacity = max(1, capacity)
    }

    public var head: Digest { entries.last?.hash ?? anchor }

    @discardableResult
    public mutating func append(_ event: ProvenanceEvent, at date: Date) -> ProvenanceEntry {
        let ms = Saturating.milliseconds(date.timeIntervalSince1970)
        let entry = ProvenanceEntry(
            sequence: nextSequence, timestampMilliseconds: ms, event: event, previous: head,
            hash: ProvenanceEntry.link(sequence: nextSequence, timestampMilliseconds: ms, event: event, previous: head))
        nextSequence = Saturating.add(nextSequence, 1)
        entries.append(entry)
        if entries.count > capacity, let oldest = entries.first {
            anchor = oldest.hash
            entries.removeFirst()
            droppedCount = Saturating.add(droppedCount, 1)
        }
        return entry
    }

    public enum Verification: Equatable, Sendable {
        case intact(entries: Int)
        case broken(atSequence: UInt64, reason: String)
    }

    /// Recompute every link from the anchor.
    public func verify() -> Verification {
        var previous = anchor
        var expectedSequence = entries.first?.sequence
        for entry in entries {
            if let expected = expectedSequence, entry.sequence != expected {
                return .broken(atSequence: entry.sequence, reason: "sequence gap (expected \(expected))")
            }
            if entry.previous != previous {
                return .broken(atSequence: entry.sequence, reason: "previous-hash link does not match")
            }
            let recomputed = ProvenanceEntry.link(sequence: entry.sequence, timestampMilliseconds: entry.timestampMilliseconds,
                                                  event: entry.event, previous: entry.previous)
            if recomputed != entry.hash {
                return .broken(atSequence: entry.sequence, reason: "entry content does not match its hash")
            }
            previous = entry.hash
            expectedSequence = Saturating.add(entry.sequence, 1)
        }
        return .intact(entries: entries.count)
    }
}
