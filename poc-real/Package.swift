// swift-tools-version: 5.10
// Real PoC — imports ContainerizationArchive from the parent repo
// to demonstrate CWE-835 via the ACTUAL StreamingIterator.next() code path.
import PackageDescription

let package = Package(
    name: "RealArchiveFatalPoC",
    platforms: [.macOS(.v14)],
    dependencies: [
        // Path dependency on the parent containerization repo —
        // this is the REAL ContainerizationArchive, not a replica.
        .package(path: ".."),
    ],
    targets: [
        .executableTarget(
            name: "MakeMalformedTar",
            path: "Sources/MakeMalformedTar"
        ),
        .executableTarget(
            name: "RealArchiveFatalPoC",
            dependencies: [
                .product(name: "ContainerizationArchive", package: "containerization"),
            ],
            path: "Sources/RealArchiveFatalPoC"
        ),
    ]
)
