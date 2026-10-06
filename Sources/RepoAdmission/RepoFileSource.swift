import Foundation

/// One entry a repository source exposes.
public struct RepoEntry: Hashable, Sendable {
    public enum Kind: Hashable, Sendable {
        case file(size: Int)
        /// A symbolic link. Never followed: a control file that is a symlink is
        /// reported as unscannable, because whatever it points at is outside
        /// the content this gate hashed.
        case symlink(target: String)
    }

    /// Repo-relative, `/`-separated path, no leading `./`.
    public let path: String
    public let kind: Kind

    public init(path: String, kind: Kind) {
        self.path = path
        self.kind = kind
    }
}

public enum RepoReadError: Error, Equatable, Sendable {
    case notFound(String)
    case tooLarge(path: String, size: Int, limit: Int)
    case enumerationLimitExceeded(limit: Int)
    case io(path: String, message: String)
}

/// Read-only view of a repository working tree, including its `.git` directory.
///
/// The scanner never touches the file system directly; it reads through this
/// protocol. That is what lets the demo app and the red-team tests run the
/// exact production scanner against an in-memory tree, and what lets the hook
/// adapter point it at a real checkout.
public protocol RepoFileSource: Sendable {
    func entries() throws -> [RepoEntry]
    /// Contents of a regular file, refusing anything larger than `limit` bytes.
    func read(_ path: String, limit: Int) throws -> [UInt8]
}

/// A repository source the sanitizer can write to.
public protocol WritableRepo: RepoFileSource {
    mutating func write(_ bytes: [UInt8], to path: String) throws
    mutating func remove(_ path: String) throws
}

/// A repository held entirely in memory. Value type: every mutation produces a
/// new snapshot, which is what makes "approve, then the tree changes" testable.
public struct InMemoryRepo: WritableRepo, Equatable {
    public private(set) var files: [String: [UInt8]]
    public private(set) var symlinks: [String: String]

    public init(files: [String: String] = [:], symlinks: [String: String] = [:]) {
        self.files = files.mapValues { Array($0.utf8) }
        self.symlinks = symlinks
    }

    public init(binaryFiles: [String: [UInt8]], symlinks: [String: String] = [:]) {
        self.files = binaryFiles
        self.symlinks = symlinks
    }

    public func entries() -> [RepoEntry] {
        let regular = files.map { RepoEntry(path: $0.key, kind: .file(size: $0.value.count)) }
        let links = symlinks.map { RepoEntry(path: $0.key, kind: .symlink(target: $0.value)) }
        return (regular + links).sorted { $0.path < $1.path }
    }

    public func read(_ path: String, limit: Int) throws -> [UInt8] {
        guard let bytes = files[path] else { throw RepoReadError.notFound(path) }
        guard bytes.count <= max(0, limit) else {
            throw RepoReadError.tooLarge(path: path, size: bytes.count, limit: limit)
        }
        return bytes
    }

    public func text(_ path: String) -> String? {
        files[path].map { String(decoding: $0, as: UTF8.self) }
    }

    public mutating func write(_ bytes: [UInt8], to path: String) {
        symlinks[path] = nil
        files[path] = bytes
    }

    public mutating func write(_ text: String, to path: String) {
        write(Array(text.utf8), to: path)
    }

    public mutating func remove(_ path: String) {
        files[path] = nil
        symlinks[path] = nil
    }
}

/// Limits that bound the cost of scanning a hostile tree.
public struct ScanLimits: Sendable, Equatable {
    /// Largest control file the scanner will read. A larger one is reported as
    /// unscannable rather than skipped: skipping is how a 40 MB `project.pbxproj`
    /// with one script phase at the end would get through.
    public var maxFileBytes: Int
    /// Hard ceiling on directory entries enumerated.
    public var maxEntries: Int
    /// Directories never descended into. `.git/objects` is content-addressed
    /// object storage git never executes; the build outputs are regenerated.
    /// `Pods` is deliberately NOT here: `Pods/Pods.xcodeproj` script phases
    /// run in every CocoaPods build.
    public var skippedDirectories: Set<String>

    public init(maxFileBytes: Int = 32 * 1024 * 1024,
                maxEntries: Int = 250_000,
                skippedDirectories: Set<String> = [".git/objects", ".git/lfs", ".build", "DerivedData", "node_modules", ".swiftpm/cache"]) {
        self.maxFileBytes = max(0, maxFileBytes)
        self.maxEntries = max(0, maxEntries)
        self.skippedDirectories = skippedDirectories
    }

    public static let `default` = ScanLimits()
}

/// A repository on disk. Never follows symbolic links.
public struct DirectoryRepo: WritableRepo {
    public let root: URL
    public let limits: ScanLimits

    public init(root: URL, limits: ScanLimits = .default) {
        self.root = root.standardizedFileURL
        self.limits = limits
    }

    public func entries() throws -> [RepoEntry] {
        let fm = FileManager.default
        var result: [RepoEntry] = []
        var pending: [String] = [""]  // repo-relative directories still to list
        var seen = 0                  // every entry, directories included
        while let dir = pending.popLast() {
            let absolute = dir.isEmpty ? root.path : root.appendingPathComponent(dir).path
            let names: [String]
            do {
                names = try fm.contentsOfDirectory(atPath: absolute)
            } catch {
                throw RepoReadError.io(path: dir.isEmpty ? "." : dir, message: "\(error)")
            }
            for name in names.sorted() {
                let relative = dir.isEmpty ? name : "\(dir)/\(name)"
                if limits.skippedDirectories.contains(relative) { continue }
                seen = Saturating.add(seen, 1)
                if seen > limits.maxEntries {
                    throw RepoReadError.enumerationLimitExceeded(limit: limits.maxEntries)
                }
                let full = root.appendingPathComponent(relative).path
                // `attributesOfItem` uses lstat semantics: a symlink is reported
                // as a symlink, not as whatever it points at.
                let attributes = try fm.attributesOfItem(atPath: full)
                let type = attributes[.type] as? FileAttributeType
                switch type {
                case .typeDirectory?:
                    pending.append(relative)
                case .typeSymbolicLink?:
                    let target = (try? fm.destinationOfSymbolicLink(atPath: full)) ?? "?"
                    result.append(RepoEntry(path: relative, kind: .symlink(target: target)))
                case .typeRegular?:
                    let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
                    result.append(RepoEntry(path: relative, kind: .file(size: size)))
                default:
                    continue  // sockets, FIFOs, devices: not code git or a build reads
                }
            }
        }
        return result.sorted { $0.path < $1.path }
    }

    public func read(_ path: String, limit: Int) throws -> [UInt8] {
        let url = root.appendingPathComponent(path)
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        } catch {
            throw RepoReadError.notFound(path)
        }
        guard (attributes[.type] as? FileAttributeType) == .typeRegular else {
            throw RepoReadError.io(path: path, message: "not a regular file")
        }
        let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
        guard size <= max(0, limit) else { throw RepoReadError.tooLarge(path: path, size: size, limit: limit) }
        do {
            let data = try Data(contentsOf: url)
            guard data.count <= max(0, limit) else {
                // The file grew between stat and read; still refuse.
                throw RepoReadError.tooLarge(path: path, size: data.count, limit: limit)
            }
            return [UInt8](data)
        } catch let error as RepoReadError {
            throw error
        } catch {
            throw RepoReadError.io(path: path, message: "\(error)")
        }
    }

    public func write(_ bytes: [UInt8], to path: String) throws {
        do {
            try Data(bytes).write(to: root.appendingPathComponent(path), options: .atomic)
        } catch {
            throw RepoReadError.io(path: path, message: "\(error)")
        }
    }

    public func remove(_ path: String) throws {
        do {
            try FileManager.default.removeItem(at: root.appendingPathComponent(path))
        } catch {
            throw RepoReadError.io(path: path, message: "\(error)")
        }
    }
}
