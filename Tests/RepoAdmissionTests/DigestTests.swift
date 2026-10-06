import XCTest
@testable import RepoAdmission

final class DigestTests: XCTestCase {
    // NIST FIPS 180-4 example vectors. A broken round function, padding or
    // length encoding changes every one of these.
    func testNISTVectors() {
        XCTAssertEqual(Digest.of("").hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(Digest.of("abc").hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(Digest.of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex,
                       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    func testMultiBlockAndPaddingBoundaries() {
        // 55, 56 and 64 bytes straddle the one-block/two-block padding boundary.
        XCTAssertEqual(Digest.of(String(repeating: "a", count: 55)).hex,
                       "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318")
        XCTAssertEqual(Digest.of(String(repeating: "a", count: 56)).hex,
                       "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a")
        XCTAssertEqual(Digest.of(String(repeating: "a", count: 64)).hex,
                       "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")
    }

    func testMillionA() {
        XCTAssertEqual(Digest.of(bytes: [UInt8](repeating: 0x61, count: 1_000_000)).hex,
                       "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    func testHexValidation() {
        XCTAssertNil(Digest(hex: ""))
        XCTAssertNil(Digest(hex: String(repeating: "g", count: 64)))
        XCTAssertNil(Digest(hex: String(repeating: "a", count: 63)))
        XCTAssertEqual(Digest(hex: String(repeating: "A", count: 64))?.hex, String(repeating: "a", count: 64))
        XCTAssertThrowsError(try JSONDecoder().decode([Digest].self, from: Data(#"["nope"]"#.utf8)))
    }

    func testCombiningIsOrderIndependentAndLengthPrefixed() {
        let a = Digest.of("a"), b = Digest.of("b")
        XCTAssertEqual(Digest.combining([("x", a), ("y", b)], domain: "d"), Digest.combining([("y", b), ("x", a)], domain: "d"))
        XCTAssertNotEqual(Digest.combining([("x", a)], domain: "d"), Digest.combining([("x", a)], domain: "e"))
        // Without length prefixes, one part whose label smuggles in the
        // separator and a second line serialises exactly like two parts:
        // "a=<a>\nb=<b>\n" either way.
        XCTAssertNotEqual(Digest.combining([("a", a), ("b", b)], domain: "d"),
                          Digest.combining([("a=\(a.hex)\nb", b)], domain: "d"))
        XCTAssertEqual(Digest.combining([], domain: "d"), Digest.combining([], domain: "d"))
    }

    func testSaturatingHelpersNeverTrap() {
        XCTAssertEqual(Saturating.add(Int.max, 1), Int.max)
        XCTAssertEqual(Saturating.add(Int.min, -1), Int.min)
        XCTAssertEqual(Saturating.add(UInt64.max, 1), UInt64.max)
        XCTAssertEqual(Saturating.milliseconds(.nan), 0)
        XCTAssertEqual(Saturating.milliseconds(.infinity), 0)
        XCTAssertEqual(Saturating.milliseconds(1e300), Int64.max)
        XCTAssertEqual(Saturating.milliseconds(-1e300), Int64.min)
        XCTAssertEqual(Saturating.milliseconds(1.5), 1500)
        XCTAssertNil([1, 2][safe: 2])
        XCTAssertNil([1, 2][safe: -1])
    }
}
