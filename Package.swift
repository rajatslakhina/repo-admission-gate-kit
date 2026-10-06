// swift-tools-version: 6.0
import PackageDescription

// This manifest is deliberately boring, and the library's own scanner checks
// that it stays that way: no plugins, no macros, no `unsafeFlags`, no remote
// dependencies, no binary targets. A gate for build-time code execution that
// itself ran code at build time would be making the argument against itself.
// `ManifestScannerTests.testThisPackagesOwnManifestHasNoExecutionVectors`
// scans this file and fails the build if that ever changes.
let package = Package(
    name: "repo-admission-gate-kit",
    // Only platforms this repository's own CI builds are declared: macOS via
    // `swift build`/`swift test` on macos-15, and iOS via the `ios-simulator`
    // job, which compiles the SwiftUI module for `generic/platform=iOS Simulator`.
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "RepoAdmission", targets: ["RepoAdmission"]),
        .library(name: "RepoAdmissionUI", targets: ["RepoAdmissionUI"]),
    ],
    targets: [
        .target(
            name: "RepoAdmission",
            swiftSettings: [.enableUpcomingFeature("ExistentialAny")]
        ),
        .target(
            name: "RepoAdmissionUI",
            dependencies: ["RepoAdmission"],
            swiftSettings: [.enableUpcomingFeature("ExistentialAny")]
        ),
        .testTarget(
            name: "RepoAdmissionTests",
            dependencies: ["RepoAdmission"]
        ),
        // The console's view model is deliberately NOT behind
        // `#if canImport(SwiftUI)` — only the views are — so the demo's own
        // logic is compiled and tested on Linux CI rather than shipping untested.
        .testTarget(
            name: "RepoAdmissionUITests",
            dependencies: ["RepoAdmissionUI", "RepoAdmission"]
        ),
    ]
)
