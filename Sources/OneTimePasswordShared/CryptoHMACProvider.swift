//
//  CryptoHMACProvider.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Foundation
import RFC_6238
import Crypto

/// HMAC provider implementation using swift-crypto
public struct CryptoHMACProvider: RFC_6238.HMACProvider {
    
    public init() {}
    
    public func hmac(algorithm: RFC_6238.Algorithm, key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        
        switch algorithm {
        case .sha1:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: symmetricKey))
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
        }
    }
}