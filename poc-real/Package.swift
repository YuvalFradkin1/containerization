// swift-tools-version: 5.10
//
// PoC for SIG-NEW — CWE-61 (Symlink Following) + CWE-22 (Path Traversal)
// apple/containerization · ArchiveWriter path-containment bypass
//
// Root cause: FilePath.appending(String) in swift-system concatenates a leading "/"
// instead of treating it as an absolute-path replacement (POSIX semantics).
// A symlink with an absolute target such as /etc/shadow is therefore resolved to
// <containerRootfs>/etc/shadow, passes the hasPrefix containment guard in
// ArchiveWriter.swift:226, and is stored verbatim in the archive.
// ArchiveReader.extractContents() then calls symlinkat(2) with the raw target on
// the HOST filesystem.
//
// This package vendors the exact source files from apple/containerization
// Sources/ContainerizationArchive/ verbatim (Sources/VendoredContainerizationArchive/).
// Minimal stubs are provided for ContainerizationOS, ContainerizationExtras, and
// ContainerizationError to allow compilation without the full parent package
// (which requires macOS 26 + Xcode 26 for non-archive targets).
//
// NOTE: We do NOT declare swift-system as a package dependency here.
// Using .product(name: "SystemPackage", package: "swift-system") causes SwiftPM to
// build swift-system from source, producing a _StrSlice.== that is
// @_alwaysEmitIntoClient with no external symbol — while compiled objects expect an
// external reference, causing an arm64 link error. Instead we rely on the
// SDK-provided SystemPackage that ships with the Swift toolchain (available on macOS
// since Swift 5.7), which is always ABI-compatible with the compiler in use.

import PackageDescription

let package = Package(
    name: "SymlinkEscapePoC",
    platforms: [.macOS(.v14)],
    dependencies: [
        // Pinned to exact revision used by apple/containerization Package.resolved (1.7.5)
        // to avoid _StrSlice ABI mismatch. Package.resolved locks this version in CI.
        .package(url: "https://github.com/apple/swift-system.git", exact: "1.7.5"),
    ],
    targets: [
        // CArchive — C target, verbatim copy from Sources/ContainerizationArchive/CArchive/.
        // Contains archive_swift_bridge.c and the libarchive headers.
        // Links system libarchive + lzma + bz2 + z + zstd (all from Homebrew on macOS CI).
        .target(
            name: "CArchive",
            dependencies: [],
            path: "Sources/VendoredContainerizationArchive/CArchive",
            sources: ["archive_swift_bridge.c"],
            publicHeadersPath: "include",
            cSettings: [
                // archive_swift_bridge.c includes <zstd.h> — give the C compiler the brew header path.
                .unsafeFlags(["-I/opt/homebrew/include"], .when(platforms: [.macOS])),
            ],
            linkerSettings: [
                .linkedLibrary("archive"),
                .linkedLibrary("lzma"),
                .linkedLibrary("bz2"),
                .linkedLibrary("z"),
                .linkedLibrary("zstd"),
                // Homebrew on Apple Silicon installs to /opt/homebrew (not in the default SDK search path).
                .unsafeFlags(["-L/opt/homebrew/lib"], .when(platforms: [.macOS])),
            ]
        ),

        // Stub modules for transitive dependencies not directly exercised by the PoC.
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
            // to @_alwaysEmitIntoClient symbols like _StrSlice.== from swift-system 1.7.5.
            swiftSettings: [.unsafeFlags(["-Onone"])]
        ),

        // VendoredContainerizationArchive — VERBATIM copy of production source files
        // from apple/containerization Sources/ContainerizationArchive/.
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
            // to @_alwaysEmitIntoClient symbols like _StrSlice.== from swift-system 1.7.5.
            swiftSettings: [.unsafeFlags(["-Onone"])]
        ),

        // SIG-NEW PoC binary — demonstrates all four stages of the vulnerability:
        //   Stage 1: FilePath.appending() concatenates absolute target → passes bounds check
        //   Stage 2: Archive entry contains the raw absolute symlinkTarget
        //   Stage 3: ArchiveReader.extractContents() creates a host-side symlink via symlinkat(2)
        //   Stage 4: The host symlink is followable; contents of the targeted host file are readable
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
