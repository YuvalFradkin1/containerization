// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "poc_real",
    platforms: [.macOS(.v14)],
    dependencies: [
        // Point at the local containerization clone
        .package(path: "/home/claude/containerization"),
    ],
    targets: [
        .executableTarget(
            name: "poc_real",
            dependencies: [
                .product(name: "ContainerizationEXT4", package: "containerization"),
            ],
            path: "Sources/poc_real"
        ),
    ]
)
