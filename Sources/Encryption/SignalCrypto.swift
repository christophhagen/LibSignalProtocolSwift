//
//  SignalCrypto.swift
//  SignalProtocolSwift-iOS
//
//  Created by User on 26.01.18.
//

import Foundation


/**
 The `SignalCrypto` struct exposes all necessary cryptocraphic functions to the protocol.
 By default CommonCrypto is used to provide these functions, but a custom provider can be
 implemented as well.
 Implement a provider that conforms to the `SignalCryptoProvider` protocol and set the `
 `SignalCrypto.provider` variable to customise the implementation.
 */
public struct SignalCrypto {

    // MARK: Public crypto provider functions

    /**
     This variable can be set to provide a custom crypto provider.
     */
    public static var provider: SignalCryptoProvider = SignalCommonCrypto()

    /**
     Create a number of secure random bytes.
     - parameter: The number of random bytes to create
     - returns: The random bytes of length `bytes`
     - throws: Should only throw errors of type `SignalError.noRandomBytes`
     */
    public static func random(bytes: Int) throws -> Data {
        return try provider.random(bytes: bytes)
    }

    /**
     Authenticate a message with the HMAC based on SHA256.
     - parameter message: The message to authenticate
     - parameter salt: The salt for the HMAC.
     - returns: The HMAC
     - throws: Should only throw errors of type `SignalError.hmacError`
     */
    static func hmacSHA256(for message: Data, with salt: Data) throws -> Data {
        return try provider.hmacSHA256(for: message, with: salt)
    }

    /**
     Return the SHA512 message digest.
     - parameter message: The message to calculate the digest for
     - returns: The SHA512 digest
     - throws: Should only throw errors of type `SignalError.digestError`
     */
    static func sha512(for message: Data) throws -> Data {
        return try provider.sha512(for: message)
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
    static func encrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try provider.encrypt(message: message, with: cipher, key: key, iv: iv)
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
    static func decrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try provider.decrypt(message: message, with: cipher, key: key, iv: iv)
    }

    // MARK: Useful helper functions

    /**
     Generate an identity key pair.  Clients should only do this once, at install time.
     - returns: The generated identity key pair data
     - throws: `SignalError` errors:
     `noRandomBytes` if the crypto provider can't provide random bytes.
     `curveError` if no public key could be created from the random private key.
     */
    public static func generateIdentityKeyPair() throws -> Data {
        return try KeyPair().protoData()
    }

    /**
     Generate a list of PreKeys.

     - note: Clients should do this at install time, and
     subsequently any time the list of PreKeys stored on the server runs low.

     - warning:
     Pre key IDs are shorts, so they will eventually be repeated.  Clients should
     store pre keys in a circular buffer, so that they are repeated as infrequently
     as possible.

     - note: The following errors can be thrown:
     - `noRandomBytes` if the crypto provider can't provide random bytes.
     - `curveError` if no public key could be created from a random private key.
     - parameter start: the starting pre key ID, inclusive.
     - parameter count: the number of pre keys to generate.
     - returns: The pre keys
     - throws: `SignalError` errors
     */
    static func generatePreKeys(start: UInt32, count: Int) throws -> [SessionPreKey] {
        var dict = [SessionPreKey]()

        for i in 0..<UInt32(count) {
            dict.append(try SessionPreKey(index: start &+ i))
        }
        return dict
    }

    /**
     Generate a signed pre key.

     - note: The following errors can be thrown:
     - `noRandomBytes`, if the crypto provider can't provide random bytes.
     - `curveError`, if no public key could be created from the random private key.
     - `invalidLength`, if the public key is more than 256 or 0 byte.
     - `invalidSignature`, if the message could not be signed.
     - parameter identityKey: the local client's private identity key.
     - parameter id: the pre key ID to assign the generated signed pre key
     - parameter timestamp: the current time, defaults to seconds from 1970
     - throws: `SignalError` errors
     */
    static func generateSignedPreKey(identityKey: PrivateKey, id: UInt32, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) throws -> SessionSignedPreKey {
        return try SessionSignedPreKey(id: id, signatureKey: identityKey, timestamp: timestamp)
    }

    /**
     Generate a sender key ID.
     - returns: The generated ID
     - throws: `SignalError` of type `noRandomBytes`, if the crypto provider can't provide random bytes.
     */
    static func generateSenderKeyId() throws -> UInt32 {
        let data = try random(bytes: 4)
        let value: UInt32 = data.withUnsafeBytes { $0.pointee }
        return value & 0x7FFFFFFF
    }

    /**
     Generate a sender key.
     - returns: The sender key bytes
     - throws: `SignalError` of type `noRandomBytes`, if the crypto provider can't provide random bytes.
     */
    static func generateSenderKey() throws -> Data {
        return try Data(random(bytes: 32))
    }

    /**
     Generate a sender signing key pair
     - returns: the generated key pair
     - throws: `SignalError` errors:
     `noRandomBytes` if the crypto provider can't provide random bytes.
     `curveError` if no public key could be created from the random private key.
     */
    static func generateSenderSigningKey() throws -> KeyPair {
        let result = try KeyPair()
        return result
    }

    /**
     SignalCrypto only has static functions and there is no need to create any instances
     */
    private init() {

    }
}
