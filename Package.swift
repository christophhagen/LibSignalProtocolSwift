// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "SignalProtocol",
    platforms: [.macOS(.v10_13), .iOS(.v11), .tvOS(.v11), .watchOS(.v4)],
    products: [
        .library(
            name: "SignalProtocol",
            targets: ["SignalProtocol"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.6.0"),
        .package(url: "https://github.com/christophhagen/Curve25519.git", .upToNextMajor(from: "2.0.0"))
    ],
    targets: [
        .target(
            name: "SignalProtocol",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "Curve25519", package: "Curve25519")
            ]
        ),
        .testTarget(name: "SignalProtocolTests", dependencies: [
            .target(name: "SignalProtocol"),
        ])
    ]
)
