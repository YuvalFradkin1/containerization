// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "ArchiveFatalPoC",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "MakeMalformedTar",
            path: "Sources/MakeMalformedTar"
        ),
        .executableTarget(
            name: "ArchiveFatalPoC",
            dependencies: [],
            path: "Sources/ArchiveFatalPoC",
            linkerSettings: [
                .linkedLibrary("archive")
            ]
        ),
    ]
)
