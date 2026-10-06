// A content address. Every allow-list entry, every approval and every
// provenance-log link in this library is a `Digest`, never a name or a label:
// a label is something an attacker can keep while changing what it points at.

/// A SHA-256 digest, stored as 64 lowercase hex characters.
public struct Digest: Hashable, Sendable, Comparable, CustomStringConvertible, Codable {
    /// 64 lowercase hex characters.
    public let hex: String

    /// Validating initialiser: exactly 64 hex characters (case-insensitive).
    public init?(hex: String) {
        let lowered = hex.lowercased()
        guard lowered.utf8.count == 64,
              lowered.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) })
        else { return nil }
        self.hex = lowered
    }

    init(bytes: [UInt8]) {
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            // `byte >> 4` and `byte & 0x0F` are both in 0...15, so both indices
            // are provably inside the 16-element table.
            out.append(Digest.hexTable[Int(byte >> 4)])
            out.append(Digest.hexTable[Int(byte & 0x0F)])
        }
        self.hex = out
    }

    private static let hexTable: [Character] = Array("0123456789abcdef")

    /// The first 12 hex characters — for display only, never for comparison.
    public var short: String { String(hex.prefix(12)) }

    public var description: String { hex }

    public static func < (lhs: Digest, rhs: Digest) -> Bool { lhs.hex < rhs.hex }

    /// SHA-256 of a UTF-8 string.
    public static func of(_ string: String) -> Digest { SHA256.hash(Array(string.utf8)) }

    /// SHA-256 of raw bytes.
    public static func of(bytes: [UInt8]) -> Digest { SHA256.hash(bytes) }

    /// An order-independent digest over a set of labelled digests.
    ///
    /// Each part is length-prefixed so `("ab","c")` and `("a","bc")` cannot
    /// collide, and the parts are sorted first so the result depends only on
    /// the *set* — two scans of the same tree in a different enumeration order
    /// must produce the same approval surface.
    public static func combining(_ parts: [(label: String, digest: Digest)], domain: String) -> Digest {
        let sorted = parts.sorted { ($0.label, $0.digest.hex) < ($1.label, $1.digest.hex) }
        var text = "\(domain)\n"
        for part in sorted {
            text += "\(part.label.utf8.count):\(part.label)=\(part.digest.hex)\n"
        }
        return .of(text)
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let value = Digest(hex: raw) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "not a 64-character hex SHA-256 digest: \(raw.prefix(80))")
        }
        self = value
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(hex)
    }
}

/// FIPS 180-4 SHA-256 in pure Swift.
///
/// Rejected alternative: CryptoKit / swift-crypto. CryptoKit does not exist on
/// Linux, and swift-crypto is a remote package — i.e. exactly the kind of
/// build-time dependency this library asks its users to justify. ~60 lines of
/// arithmetic, checked against the NIST test vectors in `SHA256Tests`, is the
/// cheaper thing to defend. It is not constant-time and does not need to be:
/// it hashes public file contents, never secrets.
enum SHA256 {
    private static let k: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    @inline(__always)
    private static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }

    static func hash(_ input: [UInt8]) -> Digest {
        var h: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        var message = input
        // Message length in bits, modulo 2^64 as the standard specifies —
        // wrapping arithmetic is the definition here, not a shortcut.
        let bitLength = UInt64(truncatingIfNeeded: message.count) &* 8
        message.append(0x80)
        while message.count % 64 != 56 { message.append(0) }
        for shift in stride(from: 56, through: 0, by: -8) {
            message.append(UInt8(truncatingIfNeeded: bitLength >> UInt64(shift)))
        }

        var w = [UInt32](repeating: 0, count: 64)
        var chunk = 0
        // `message.count` is a multiple of 64 by construction (padding above),
        // so every index below is `chunk + 0...63` with `chunk + 63 < count`.
        while chunk + 64 <= message.count {
            for t in 0..<16 {
                let b = chunk + t * 4
                w[t] = UInt32(message[b]) << 24 | UInt32(message[b + 1]) << 16
                    | UInt32(message[b + 2]) << 8 | UInt32(message[b + 3])
            }
            for t in 16..<64 {
                let s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
                let s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
                w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
            }
            var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
            for t in 0..<64 {
                let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
                let ch = (e & f) ^ (~e & g)
                let temp1 = hh &+ s1 &+ ch &+ k[t] &+ w[t]
                let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = s0 &+ maj
                hh = g; g = f; f = e; e = d &+ temp1
                d = c; c = b; b = a; a = temp1 &+ temp2
            }
            h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d
            h[4] = h[4] &+ e; h[5] = h[5] &+ f; h[6] = h[6] &+ g; h[7] = h[7] &+ hh
            chunk += 64
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        for word in h {
            bytes.append(UInt8(truncatingIfNeeded: word >> 24))
            bytes.append(UInt8(truncatingIfNeeded: word >> 16))
            bytes.append(UInt8(truncatingIfNeeded: word >> 8))
            bytes.append(UInt8(truncatingIfNeeded: word))
        }
        return Digest(bytes: bytes)
    }
}

/// Saturating arithmetic for counters that must never trap, whatever the input.
enum Saturating {
    static func add(_ a: Int, _ b: Int) -> Int {
        let (value, overflow) = a.addingReportingOverflow(b)
        return overflow ? (b > 0 ? Int.max : Int.min) : value
    }

    static func add(_ a: UInt64, _ b: UInt64) -> UInt64 {
        let (value, overflow) = a.addingReportingOverflow(b)
        return overflow ? UInt64.max : value
    }

    /// Milliseconds since 1970 as `Int64`, clamped; NaN and ±infinity map to 0
    /// and the range ends instead of trapping in `Int64(Double)`.
    static func milliseconds(_ seconds: Double) -> Int64 {
        let ms = seconds * 1000
        guard ms.isFinite else { return 0 }
        if ms >= 9.2e18 { return Int64.max }
        if ms <= -9.2e18 { return Int64.min }
        return Int64(ms.rounded())
    }
}

extension Array {
    /// Bounds-checked element access: `nil` instead of a trap.
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
