// swift-tools-version: 5.10
//
// Real PoC for SIG-01 — CWE-835 (ARCHIVE_FATAL infinite loop)
//
// This package vendors the exact source files from apple/containerization
// Sources/ContainerizationArchive/ verbatim (see Sources/VendoredContainerizationArchive/).
// Minimal shims are provided for ContainerizationOS, ContainerizationExtras,
// and ContainerizationError to allow compilation without the full parent package
// (which requires macOS 26 + Xcode 26 for non-archive targets).
//
// The PoC exercises ArchiveReader.makeStreamingIterator() using the REAL source code,
// proving the bug exists in apple/containerization — not a standalone replica.
//
// NOTE: We intentionally do NOT declare swift-system as a package dependency.
// Using .product(name: "SystemPackage", package: "swift-system") causes SwiftPM
// to build swift-system from source, producing a version of _StrSlice.== that
// is @_alwaysEmitIntoClient and therefore has no external symbol — while the
// compiled object files expect an external reference, causing an arm64 link error.
// Instead we rely on the SDK-provided SystemPackage that ships with the Swift
// toolchain (available on macOS since Swift 5.7), which is always ABI-compatible
// with the compiler in use.
import PackageDescription

let package = Package(
    name: "RealArchiveFatalPoC",
    platforms: [.macOS(.v14)],
    dependencies: [
        // Pinned to exact revision used by apple/containerization Package.resolved (1.7.5)
        // to avoid _StrSlice ABI mismatch. A Package.resolved locks this version on CI.
        .package(url: "https://github.com/apple/swift-system.git", exact: "1.7.5"),
    ],
    targets: [
        // CArchive — C target, verbatim copy from Sources/ContainerizationArchive/CArchive/
        // Contains archive_swift_bridge.c and the libarchive headers.
        // Links system libarchive + lzma + bz2 + z + zstd (all from Homebrew on macOS CI).
        .target(
            name: "CArchive",
            dependencies: [],
            path: "Sources/VendoredContainerizationArchive/CArchive",
            sources: ["archive_swift_bridge.c"],
            publicHeadersPath: "include",
            cSettings: [
                // archive_swift_bridge.c includes <zstd.h> — give the C compiler the brew header path
                .unsafeFlags(["-I/opt/homebrew/include"], .when(platforms: [.macOS])),
            ],
            linkerSettings: [
                .linkedLibrary("archive"),
                .linkedLibrary("lzma"),
                .linkedLibrary("bz2"),
                .linkedLibrary("z"),
                .linkedLibrary("zstd"),
                // Homebrew on Apple Silicon installs to /opt/homebrew (not in default SDK search path)
                .unsafeFlags(["-L/opt/homebrew/lib"], .when(platforms: [.macOS])),
            ]
        ),

        // Stub modules for transitive dependencies we don't exercise
        .target(
            name: "ContainerizationError",
            path: "Sources/ContainerizationError"
        ),
        .target(
            name: "ContainerizationExtras",
            path: "Sources/ContainerizationExtras"
        ),
        .target(
            name: "ContainerizationOS",
            dependencies: [
                .product(name: "SystemPackage", package: "swift-system"),
            ],
            path: "Sources/ContainerizationOS",
            // -Onone prevents the Swift 6 compiler from emitting external references
            // to @_alwaysEmitIntoClient symbols like _StrSlice.== from swift-system 1.7.5
            swiftSettings: [.unsafeFlags(["-Onone"])]
        ),

        // Vendored ContainerizationArchive — VERBATIM copy of real source files
        // from apple/containerization Sources/ContainerizationArchive/
        .target(
            name: "VendoredContainerizationArchive",
            dependencies: [
                "CArchive",
                "ContainerizationError",
                "ContainerizationOS",
                "ContainerizationExtras",
                .product(name: "SystemPackage", package: "swift-system"),
            ],
            path: "Sources/VendoredContainerizationArchive",
            exclude: ["CArchive"],
            // -Onone prevents the Swift 6 compiler from emitting external references
            // to @_alwaysEmitIntoClient symbols like _StrSlice.== from swift-system 1.7.5
            swiftSettings: [.unsafeFlags(["-Onone"])]
        ),

        // Malformed tar generator (standalone, no archive dependency)
        .executableTarget(
            name: "MakeMalformedTar",
            path: "Sources/MakeMalformedTar"
        ),

        // Main PoC binary
        .executableTarget(
            name: "RealArchiveFatalPoC",
            dependencies: [
                "VendoredContainerizationArchive",
            ],
            path: "Sources/RealArchiveFatalPoC"
        ),

        // SIG-NEW: Container → Host Symlink Exfiltration via ArchiveWriter.archiveDirectory
        // CWE-61 / CWE-22 — FilePath.appending(String) concatenates absolute targets
        // instead of replacing the base, bypassing the containment guard.
        .executableTarget(
            name: "SymlinkEscapePoC",
            dependencies: [
                "VendoredContainerizationArchive",
            ],
            path: "Sources/SymlinkEscapePoC",
            swiftSettings: [.unsafeFlags(["-Onone"])]
        ),
    ]
)
