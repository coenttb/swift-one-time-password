//
//  ReadmeVerificationTests.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-10-31.
//

import Crypto
import Dependencies
import DependenciesTestSupport
import Foundation
import OneTimePasswordShared
import Testing

@testable import HOTP
@testable import TOTP

@Suite(
  "README Verification",
  .dependency(\.date, .init { Date() })
)
struct ReadmeVerificationTests {

  // MARK: - TOTP Examples from README

  @Test("README Example - Basic TOTP Generation (lines 50-71)")
  func readmeExampleBasicTOTPGeneration() throws {
    // From README lines 50-71
    // Create TOTP from base32 secret (most common format)
    let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")

    // Generate current OTP
    let code = totp.generate()
    #expect(!code.isEmpty)
    #expect(code.count == 6)

    // Or use the convenience property
    let currentCode = totp.currentOTP
    #expect(!currentCode.isEmpty)

    // Validate an OTP
    if totp.validate(code) {
      // Valid OTP!
    }

    // Check time remaining for current code
    let remaining = totp.timeRemaining()
    #expect(remaining > 0)
    #expect(remaining <= 30)
  }

  @Test("README Example - Generate Secure Secrets (lines 73-86)")
  func readmeExampleGenerateSecrets() throws {
    // From README lines 73-86
    // Generate a random base32 secret
    let secret = TOTP.generateSecret()  // Default 20 bytes for SHA1
    #expect(!secret.isEmpty)

    // Create TOTP with newly generated secret
    let totp = try TOTP.generateNew(algorithm: .sha256, digits: 6)
    let code = totp.generate()
    #expect(code.count == 6)

    // Get the base32 secret for sharing
    let base32Secret = totp.base32Secret
    #expect(!base32Secret.isEmpty)
  }

  @Test("README Example - Different Hash Algorithms (lines 88-99)")
  func readmeExampleDifferentAlgorithms() throws {
    // From README lines 88-99
    let secret = TOTP.generateSecret()

    // SHA1 (default, most compatible with authenticator apps)
    let sha1TOTP = try TOTP.sha1(base32Secret: secret)
    #expect(sha1TOTP.algorithm == .sha1)

    // SHA256 (more secure)
    let sha256TOTP = try TOTP.sha256(base32Secret: secret, digits: 8)
    #expect(sha256TOTP.algorithm == .sha256)
    #expect(sha256TOTP.digits == 8)

    // SHA512 (maximum security)
    let sha512TOTP = try TOTP.sha512(base32Secret: secret)
    #expect(sha512TOTP.algorithm == .sha512)
  }

  @Test("README Example - Provisioning URI (lines 101-113)")
  func readmeExampleProvisioningURI() throws {
    // From README lines 101-113
    let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
    let uri = totp.provisioningURI(
      label: "user@example.com",
      issuer: "My App"
    )

    // Verify URI format
    #expect(uri.starts(with: "otpauth://totp/"))
    #expect(uri.contains("secret=JBSWY3DPEHPK3PXP"))
    #expect(uri.contains("issuer=My%20App"))
  }

  @Test("README Example - Time Window Validation (lines 115-129)")
  func readmeExampleTimeWindowValidation() throws {
    // From README lines 115-129
    let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
    let userInput = totp.generate()

    // Validate with time window (allows codes from adjacent time steps)
    // Useful for handling clock skew between client and server
    let validWithWindow = totp.validate(userInput, window: 1)
    // Valid within ±1 time step (usually ±30 seconds)
    #expect(validWithWindow)

    // Stricter validation (exact time step only)
    let validExact = totp.validate(userInput, window: 0)
    // Valid only for current 30-second window
    #expect(validExact)
  }

  @Test("README Example - Migration Support (lines 131-145)")
  func readmeExampleMigrationSupport() throws {
    // From README lines 131-145
    let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")

    // Export for migration (e.g., to backup or transfer to another device)
    let params = totp.exportMigration(
      issuer: "My Service",
      accountName: "user@example.com"
    )

    #expect(params.issuer == "My Service")
    #expect(params.accountName == "user@example.com")

    // Import from migration parameters
    let imported = try TOTP.from(migration: params)
    let code = imported.generate()
    #expect(code.count == 6)
  }

  // MARK: - HOTP Examples from README

  @Test("README Example - Basic HOTP Generation (lines 149-169)")
  func readmeExampleBasicHOTPGeneration() throws {
    // From README lines 149-169
    // Create HOTP with secret
    let secret = "12345678901234567890".data(using: .ascii)!
    let hotp = try HOTP(secret: secret, digits: 6)

    // Generate OTP for counter value
    let code = hotp.generate(counter: 1)
    #expect(code.count == 6)

    // Increment counter for next code
    let nextCode = hotp.generate(counter: 2)
    #expect(nextCode.count == 6)
    #expect(code != nextCode)

    // Validate a code for a specific counter
    let isValid = hotp.validate(code, counter: 1)
    #expect(isValid)
  }

  @Test("README Example - HOTP Different Algorithms (lines 171-184)")
  func readmeExampleHOTPDifferentAlgorithms() throws {
    // From README lines 171-184
    let secret = "12345678901234567890".data(using: .ascii)!

    // SHA256 (more secure than SHA1)
    let hotp256 = try HOTP(secret: secret, digits: 6, algorithm: .sha256)
    let code256 = hotp256.generate(counter: 1)
    #expect(code256.count == 6)

    // SHA512 (maximum security)
    let hotp512 = try HOTP(secret: secret, digits: 8, algorithm: .sha512)
    let code512 = hotp512.generate(counter: 1)
    #expect(code512.count == 8)

    // From base32 secret
    let hotpBase32 = try HOTP(base32Secret: "JBSWY3DPEHPK3PXP", algorithm: .sha256)
    let codeBase32 = hotpBase32.generate(counter: 1)
    #expect(codeBase32.count == 6)
  }

  // MARK: - Dependency Injection Example

  @Test("README Example - Testing with Dependency Injection (lines 230-244)")
  func readmeExampleDependencyInjection() throws {
    // From README lines 230-244
    try withDependencies {
      $0.date = .constant(Date(timeIntervalSince1970: 1_234_567_890))
    } operation: {
      let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
      let code = totp.generate()
      // Code will be deterministic due to fixed time
      #expect(code.count == 6)
    }
  }

  // MARK: - Installation Examples

  @Test("README Example - Package Dependencies Compile Check")
  func readmeExamplePackageDependenciesCompile() {
    // Verify the README package declaration compiles conceptually
    // This doesn't actually test Package.swift but verifies the described usage is correct

    // From README lines 29-32:
    // dependencies: [
    //     .package(url: "https://github.com/coenttb/swift-one-time-password.git", from: "0.0.1")
    // ]

    // From README lines 35-44:
    // .target(
    //     name: "YourApp",
    //     dependencies: [
    //         .product(name: "TOTP", package: "swift-one-time-password"),
    //         // or
    //         .product(name: "HOTP", package: "swift-one-time-password")
    //     ]
    // )

    // Verify both products exist and can be imported
    let totpExists = true  // We successfully imported TOTP at top of file
    let hotpExists = true  // We successfully imported HOTP at top of file
    #expect(totpExists && hotpExists)
  }

  // MARK: - Verify All README Code Patterns Work

  @Test("Verify README Pattern - SymmetricKey Integration")
  func readmePatternSymmetricKey() throws {
    // While not explicitly in README, this is implied by the API
    let key = SymmetricKey(size: .bits256)
    let totp = try TOTP(symmetricKey: key, algorithm: .sha256)

    #expect(totp.algorithm == .sha256)
    let code = totp.generate()
    #expect(code.count == 6)
    #expect(totp.validate(code))
  }

  @Test("Verify README Pattern - Base32 Secret Property")
  func readmePatternBase32Secret() throws {
    // Referenced in README line 84
    let originalSecret = "JBSWY3DPEHPK3PXP"
    let totp = try TOTP.sha1(base32Secret: originalSecret)

    let exportedSecret = totp.base32Secret
    #expect(exportedSecret == originalSecret)
  }

  @Test("Verify README Pattern - Time Remaining")
  func readmePatternTimeRemaining() throws {
    // Referenced in README line 69
    let totp = try TOTP.generateNew()

    let remaining = totp.timeRemaining()
    #expect(remaining > 0)
    #expect(remaining <= 30)
  }
}
