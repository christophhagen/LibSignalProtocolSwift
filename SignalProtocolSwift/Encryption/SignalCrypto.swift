//
//  SignalCrypto.swift
//  libsignal-protocol-swift
//
//  Created by User on 07.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Specifies the type of algorithm to use for encryption and decryption.
 */
public enum SignalEncryptionScheme {
    /// Encrypt/decrypt with AES in CBC mode with PKCS5 padding
    case AES_CBCwithPKCS5
    /// Encrypt/decrypt with AES in CTR mode with no padding
    case AES_CTRnoPadding
}

public protocol SignalCryptoProvider {
    /**
     Create a number of secure random bytes.
     - parameter bytes: The number of random bytes to create
     - returns: The random bytes of length `bytes`
     - throws: Should only throw errors of type `SignalError.noRandomBytes`
     */
    func random(bytes: Int) throws -> [UInt8]

    /**
     Authenticate a message with the HMAC based on SHA256.
     - parameter message: The message to authenticate
     - salt: The salt for the HMAC.
     - returns: The HMAC
     - throws: Should only throw errors of type `SignalError.hmacError`
    */
    func hmacSHA256(for message: [UInt8], with salt: [UInt8]) throws -> [UInt8]

    /**
     Return the SHA512 message digest.
     - parameter message: The message to calculate the digest for
     - returns: The SHA512 digest
     - throws: Should only throw errors of type `SignalError.digestError`
    */
    func sha512(for message: [UInt8]) throws -> [UInt8]

    /**
     Encrypt a message with the given scheme.
     - parameter message: The data to encrypt
     - parameter cipher: The encryption type to use, see `SignalEncryptionScheme`
     - parameter key: The encryption key
     - parameter iv: The initialization vector
     - returns: The encrypted message
     - throws: Should only throw errors of type `SignalError.encryptionError`
    */
    func encrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8]

    /**
     Decrypt a message with the given scheme.
     - parameter message: The data to decrypt
     - parameter cipher: The encryption type to use, see `SignalEncryptionScheme`
     - parameter key: The encryption key
     - parameter iv: The initialization vector
     - returns: The decrypted message
     - throws: Should only throw errors of type `SignalError.decryptionError`
     */
    func decrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8]

}

public struct SignalCrypto {

    /**
     This variable can be set to provide custom crypto provider.
    */
    public static var provider: SignalCryptoProvider? = SignalCommonCrypto()

    /**
     Create a number of secure random bytes.
     - parameter: The number of random bytes to create
     - returns: The random bytes of length `bytes`
     - throws: Should only throw errors of type `SignalError.noRandomBytes`
     */
    public static func random(bytes: Int) throws -> [UInt8] {
        guard let delegate = provider else {
            throw SignalError(.noCryptoProvider, "No Crypto delegate set")
        }
        return try delegate.random(bytes: bytes)
    }

    /**
     Authenticate a message with the HMAC based on SHA256.
     - parameter message: The message to authenticate
     - salt: The salt for the HMAC.
     - returns: The HMAC
     - throws: Should only throw errors of type `SignalError.hmacError`
     */
    static func hmacSHA256(for message: [UInt8], with salt: [UInt8]) throws -> [UInt8] {
        guard let delegate = provider else {
            throw SignalError(.noCryptoProvider, "No Crypto delegate set")
        }
        return try delegate.hmacSHA256(for: message, with: salt)
    }

    /**
     Return the SHA512 message digest.
     - parameter message: The message to calculate the digest for
     - returns: The SHA512 digest
     - throws: Should only throw errors of type `SignalError.digestError`
     */
    static func sha512(for message: [UInt8]) throws -> [UInt8] {
        guard let delegate = provider else {
            throw SignalError(.noCryptoProvider, "No Crypto delegate set")
        }
        return try delegate.sha512(for: message)
    }

    /**
     Encrypt a message with the given scheme.
     - parameter message: The data to encrypt
     - parameter cipher: The encryption type to use, see `SignalEncryptionScheme`
     - parameter key: The encryption key
     - parameter iv: The initialization vector
     - returns: The encrypted message
     - throws: Should only throw errors of type `SignalError.encryptionError`
     */
    static func encrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard let delegate = provider else {
            throw SignalError(.noCryptoProvider, "No Crypto delegate set")
        }
        return try delegate.encrypt(message: message, with: cipher, key: key, iv: iv)
    }

    /**
     Decrypt a message with the given scheme.
     - parameter message: The data to decrypt
     - parameter cipher: The encryption type to use, see `SignalEncryptionScheme`
     - parameter key: The encryption key
     - parameter iv: The initialization vector
     - returns: The decrypted message
     - throws: Should only throw errors of type `SignalError.decryptionError`
     */
    static func decrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        guard let delegate = provider else {
            throw SignalError(.noCryptoProvider, "No Crypto delegate set")
        }
        return try delegate.decrypt(message: message, with: cipher, key: key, iv: iv)
    }

    static func getRandomSequence(max: Int32) throws -> Int32 {
        let data = try random(bytes: 4)
        let value = Int32(from: data)!
        return value & 0x7FFFFFFF % max
    }

    public static func generateIdentityKeyPair() throws -> KeyPair {
        return try KeyPair()
    }

    public static func generateRegistrationId(extendedRange: Bool) throws -> UInt32 {
        let range = extendedRange ? UInt32(Int32.max) - 1 : 16380

        let data = try random(bytes: 4)
        let value = UInt32(from: data)!

        return value % range + 1
    }

    public static func generatePreKeys(start: UInt32, count: Int) throws -> [UInt32 : SessionPreKey] {
        var dict = [UInt32 : SessionPreKey]()

        for i in 0..<UInt32(count) {
            let ecPair = try KeyPair()
            let id = (start - 1 + i) % (SessionPreKey.mediumMaxValue - 1) + 1
            dict[id] = SessionPreKey(id: id, keyPair: ecPair)
        }
        return dict
    }

    static func generateSenderKeyId() throws -> UInt32 {
        let data = try random(bytes: 4)
        let value = UInt32(from: data)!
        return value & 0x7FFFFFFF
    }

    static func generateSenderKey() throws -> [UInt8] {
       return try random(bytes: 32)
    }

    static func generateSenderSigningKey() throws -> KeyPair {
        let result = try KeyPair()
        return result
    }

    public static func generateSignedPreKey(identitykeyPair: RatchetIdentityKeyPair, id: UInt32, timestamp: UInt64) throws -> SessionSignedPreKey {

        let ecPair = try KeyPair()

        let signature = try identitykeyPair.privateKey.sign(message: ecPair.publicKey.data)

        return SessionSignedPreKey(
            id: id,
            timestamp: timestamp,
            keyPair: ecPair,
            signature: signature)
    }
}
