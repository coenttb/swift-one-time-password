//
//  TOTP.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import OneTimePasswordShared
import Foundation
import Dependencies

public typealias TOTP = RFC_6238.TOTP

extension TOTP {
    /// Convenience accessor for the OTP at the current time
    public var currentOTP: String {
        generate()
    }
    
    /// The secret key as a base32 encoded string
    public var base32Secret: String {
        secret.base32EncodedString()
    }
    
    /// Generates an OTP for the current time using swift-crypto
    /// - Returns: The generated OTP as a string with leading zeros if necessary
    public func generate() -> String {
        @Dependency(\.date) var date
        return generate(at: date())
    }
    
    /// Generates an OTP for a given time using swift-crypto
    /// - Parameter time: The time to generate OTP for
    /// - Returns: The generated OTP as a string with leading zeros if necessary
    public func generate(at time: Date) -> String {
        generate(at: time, using: CryptoHMACProvider())
    }
    
    /// Validates an OTP at the current time using swift-crypto
    /// - Parameters:
    ///   - otp: The OTP to validate
    ///   - window: The number of time steps to check before and after current time (default: 1)
    /// - Returns: True if the OTP is valid within the window
    public func validate(_ otp: String, window: Int = 1) -> Bool {
        @Dependency(\.date) var date
        return validate(otp, at: date(), window: window)
    }
    
    /// Validates an OTP at a specific time using swift-crypto
    /// - Parameters:
    ///   - otp: The OTP to validate
    ///   - time: The time to validate against
    ///   - window: The number of time steps to check before and after the time (default: 1)
    /// - Returns: True if the OTP is valid within the window
    public func validate(_ otp: String, at time: Date, window: Int = 1) -> Bool {
        validate(otp, at: time, window: window, using: CryptoHMACProvider())
    }
    
    /// Generates multiple OTPs for display (current and next)
    /// - Parameter count: Number of OTPs to generate (default: 2)
    /// - Returns: Array of tuples with OTP and time remaining
    public func generateSequence(count: Int = 2) -> [(otp: String, timeRemaining: TimeInterval)] {
        @Dependency(\.date) var date
        let now = date()
        var results: [(String, TimeInterval)] = []
        
        for i in 0..<count {
            let time = Date(timeIntervalSince1970: now.timeIntervalSince1970 + Double(i) * timeStep)
            let otp = generate(at: time)
            let remaining = timeRemaining(at: time)
            results.append((otp, remaining))
        }
        
        return results
    }
}