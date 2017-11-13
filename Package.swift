//
//  Package.swift
//  SignalProtocolSwift
//
//  Created by User on 13.11.17.
//

import PackageDescription

let package = Package(
    name: "dealer",
    products: [
        .library(name: "SignalProtocolSwift", targets: ["SignalProtocolSwift"]),
        ],
    dependencies: [
        // Use Protocol buffers for loacal storage and message exchange.
        .Package(url: "https://github.com/apple/swift-protobuf.git", Version(1,0,1))
        ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SignalProtocolSwift",
            dependencies: ["SwiftProtobuf"]),

        .target(
            name: "SignalProtocolSwiftMacOS",
            dependencies: ["SwiftProtobuf"]),

        .testTarget(
            name: "SignalProtocolSwiftTests",
            dependencies: ["SwiftProtobuf", "SignalProtocolSwift"]),
    ],
    swiftLanguageVersions: [4]
)
