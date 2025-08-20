//
//  HOTP.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import OneTimePasswordShared
import Foundation

public typealias HOTP = RFC_6238.HOTP

extension HOTP {
    /// Generates an OTP for a given counter using swift-crypto
    /// - Parameter counter: The counter value
    /// - Returns: The generated OTP as a string with leading zeros if necessary
    public func generate(counter: UInt64) -> String {
        generate(counter: counter, using: CryptoHMACProvider())
    }
}