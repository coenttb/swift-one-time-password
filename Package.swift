// swift-tools-version:6.0

import Foundation
import PackageDescription

extension String {
    static let oneTimePasswordShared: Self = "OneTimePasswordShared"
    static let totp: Self = "TOTP"
    static let hotp: Self = "HOTP"
}

extension Target.Dependency {
    static var oneTimePasswordShared: Self { .target(name: .oneTimePasswordShared) }
    static var totp: Self { .target(name: .totp) }
    static var hotp: Self { .target(name: .hotp) }
}

extension Target.Dependency {
    static var crypto: Self { .product(name: "Crypto", package: "swift-crypto") }
    static var dependencies: Self { .product(name: "Dependencies", package: "swift-dependencies") }
    static var dependenciesTestSupport: Self { .product(name: "DependenciesTestSupport", package: "swift-dependencies") }
    static var rfc6238: Self { .product(name: "RFC_6238", package: "swift-rfc-6238") }
}

let package = Package(
    name: "swift-one-time-password",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(name: .totp, targets: [.totp]),
        .library(name: .hotp, targets: [.hotp]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto", from: "4.1.0"),
        .package(url: "https://github.com/pointfreeco/swift-dependencies", from: "1.9.2"),
        .package(url: "https://github.com/swift-web-standards/swift-rfc-6238.git", from: "0.0.1")
    ],
    targets: [
        .target(
            name: .oneTimePasswordShared,
            dependencies: [
                .rfc6238,
                .crypto
            ]
        ),
        .target(
            name: .totp,
            dependencies: [
                .oneTimePasswordShared,
                .dependencies
            ]
        ),
        .target(
            name: .hotp,
            dependencies: [
                .oneTimePasswordShared
            ]
        ),
        .testTarget(
            name: .totp.tests,
            dependencies: [
                .totp,
                .dependenciesTestSupport,
                .crypto
            ]
        ),
        .testTarget(
            name: .hotp.tests,
            dependencies: [
                .hotp,
                .dependenciesTestSupport,
                .crypto
            ]
        )
    ],
    swiftLanguageModes: [.v6]
)

extension String { var tests: Self { self + " Tests" } }
