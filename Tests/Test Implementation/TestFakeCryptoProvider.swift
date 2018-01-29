//
//  TestFakeCryptoProvider.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 12.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
import SignalProtocol

/**
 Use CommonCrypto, but use predictable random numbers
 */
class TestFakeCryptoProvider: SignalCryptoProvider {

    /// Delegate everything except random numbers to CommonCrypto
    private let delegate = SignalCommonCrypto()

    /// Current "random" value
    private var testRandom: UInt8 = 0

    /**
     Create a number of secure random bytes.
     - parameter bytes: The number of random bytes to create
     - returns: The random bytes of length `bytes`
     */
    func random(bytes: Int) -> Data {
        var output = Data(count: bytes)
        for i in 0..<bytes {
            output[i] = testRandom
            testRandom = testRandom &+ 1
        }
        return output
    }

    /**
     Authenticate a message with the HMAC based on SHA256.
     - parameter message: The message to authenticate
     - salt: The salt for the HMAC.
     - returns: The HMAC
     */
    func hmacSHA256(for message: Data, with salt: Data) -> Data {
        return delegate.hmacSHA256(for: message, with: salt)
    }

    /**
     Create a SHA512 digest for a given message
     - parameter message: The input message to create the digest for
     - returns: The digest
     - throws: `SignalError.digestError`
     */
    func sha512(for message: Data) throws -> Data {
        return try delegate.sha512(for: message)
    }

    /**
     Encrypt a message with AES
     - parameter message: The input message to encrypt
     - parameter cipher: THe encryption scheme to use
     - parameter key: The key for encryption (`kCCKeySizeAES128` bytes)
     - parameter iv: The initialization vector
     - returns: The encrypted message
     - throws: `SignalError.encryptionError`
     */
    func encrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try delegate.encrypt(message: message, with: cipher, key: key, iv: iv)
    }

    /**
     Decrypt a message with AES
     - parameter message: The input message to decrypt
     - parameter cipher: THe encryption scheme to use
     - parameter key: The key for decryption (`kCCKeySizeAES128` bytes)
     - parameter iv: The initialization vector
     - returns: The decrypted message
     - throws: `SignalError.decryptionError`
     */
    func decrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try delegate.decrypt(message: message, with: cipher, key: key, iv: iv)
    }
}
