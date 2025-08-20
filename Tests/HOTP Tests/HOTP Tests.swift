//
//  HOTP Tests.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Testing
import Foundation
@testable import HOTP
import OneTimePasswordShared

@Suite("HOTP Tests")
struct HOTPTests {
    
    @Test("HOTP Generation - RFC 4226 Test Vectors")
    func testHOTPGeneration() throws {
        // Test vector from RFC 4226
        let secret = "12345678901234567890".data(using: .ascii)!
        let hotp = try HOTP(secret: secret, digits: 6)
        
        // These are truncated values from RFC 4226 Appendix D
        let expectedValues = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489"
        ]
        
        for (counter, expected) in expectedValues.enumerated() {
            let otp = hotp.generate(counter: UInt64(counter))
            #expect(otp == expected, "HOTP counter \(counter) should generate \(expected), got \(otp)")
        }
    }
    
    @Test("HOTP with Different Digit Lengths")
    func testHOTPDigitLengths() throws {
        let secret = "12345678901234567890".data(using: .ascii)!
        
        // Test 6 digits
        let hotp6 = try HOTP(secret: secret, digits: 6)
        let otp6 = hotp6.generate(counter: 0)
        #expect(otp6.count == 6)
        #expect(otp6 == "755224")
        
        // Test 7 digits
        let hotp7 = try HOTP(secret: secret, digits: 7)
        let otp7 = hotp7.generate(counter: 0)
        #expect(otp7.count == 7)
        
        // Test 8 digits
        let hotp8 = try HOTP(secret: secret, digits: 8)
        let otp8 = hotp8.generate(counter: 0)
        #expect(otp8.count == 8)
    }
    
    @Test("HOTP with Different Algorithms")
    func testHOTPAlgorithms() throws {
        let secret = Data(repeating: 0x42, count: 32)
        let counter: UInt64 = 12345
        
        // Test SHA1
        let hotpSHA1 = try HOTP(secret: secret, digits: 6, algorithm: .sha1)
        let otpSHA1 = hotpSHA1.generate(counter: counter)
        #expect(otpSHA1.count == 6)
        
        // Test SHA256
        let hotpSHA256 = try HOTP(secret: secret, digits: 6, algorithm: .sha256)
        let otpSHA256 = hotpSHA256.generate(counter: counter)
        #expect(otpSHA256.count == 6)
        
        // Test SHA512
        let hotpSHA512 = try HOTP(secret: secret, digits: 6, algorithm: .sha512)
        let otpSHA512 = hotpSHA512.generate(counter: counter)
        #expect(otpSHA512.count == 6)
        
        // Different algorithms should produce different OTPs
        #expect(otpSHA1 != otpSHA256)
        #expect(otpSHA256 != otpSHA512)
        #expect(otpSHA1 != otpSHA512)
    }
    
    @Test("HOTP Counter Overflow")
    func testHOTPCounterOverflow() throws {
        let secret = Data(repeating: 0x42, count: 20)
        let hotp = try HOTP(secret: secret, digits: 6)
        
        // Test with maximum counter value
        let maxCounter = UInt64.max
        let otp = hotp.generate(counter: maxCounter)
        #expect(otp.count == 6)
    }
    
    @Test("HOTP Base32 Secret")
    func testHOTPBase32Secret() throws {
        let base32Secret = "JBSWY3DPEHPK3PXP"
        let hotp = try HOTP(base32Secret: base32Secret, digits: 6)
        
        let otp = hotp.generate(counter: 0)
        #expect(otp.count == 6)
    }
    
    @Test("HOTP Error Handling")
    func testHOTPErrors() throws {
        // Test empty secret
        #expect(throws: RFC_6238.Error.emptySecret) {
            _ = try HOTP(secret: Data(), digits: 6)
        }
        
        // Test invalid digits (too few)
        #expect(throws: RFC_6238.Error.self) {
            _ = try HOTP(secret: Data(repeating: 0x42, count: 20), digits: 5)
        }
        
        // Test invalid digits (too many)
        #expect(throws: RFC_6238.Error.self) {
            _ = try HOTP(secret: Data(repeating: 0x42, count: 20), digits: 9)
        }
        
        // Test invalid base32
        #expect(throws: RFC_6238.Error.invalidBase32String) {
            _ = try HOTP(base32Secret: "INVALID!@#$%", digits: 6)
        }
    }
}