//
//  SignalCryptoProvider.swift
//  SignalProtocolSwift
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

/**
 The `SignalCryptoProvider` protocol can be implemented to provide a custom
 implementation of the cryptographic functions. Set the crypto provider
 by setting the static `provider` variable of the SignalCrypto class
 */
public protocol SignalCryptoProvider {

    /**
     Create a number of secure random bytes.
     - parameter bytes: The number of random bytes to create
     - returns: The random bytes of length `bytes`
     - throws: Should only throw errors of type `SignalError.noRandomBytes`
     */
    func random(bytes: Int) throws -> Data

    /**
     Authenticate a message with the HMAC based on SHA256.
     - parameter message: The message to authenticate
     - salt: The salt for the HMAC.
     - returns: The HMAC
     - throws: Should only throw errors of type `SignalError.hmacError`
     */
    func hmacSHA256(for message: Data, with salt: Data) throws -> Data

    /**
     Return the SHA512 message digest.
     - parameter message: The message to calculate the digest for
     - returns: The SHA512 digest
     - throws: Should only throw errors of type `SignalError.digestError`
     */
    func sha512(for message: Data) throws -> Data

    /**
     Encrypt a message with the given scheme.
     - parameter message: The data to encrypt
     - parameter cipher: The encryption type to use, see `SignalEncryptionScheme`
     - parameter key: The encryption key
     - parameter iv: The initialization vector
     - returns: The encrypted message
     - throws: Should only throw errors of type `SignalError.encryptionError`
     */
    func encrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data

    /**
     Decrypt a message with the given scheme.
     - parameter message: The data to decrypt
     - parameter cipher: The encryption type to use, see `SignalEncryptionScheme`
     - parameter key: The encryption key
     - parameter iv: The initialization vector
     - returns: The decrypted message
     - throws: Should only throw errors of type `SignalError.decryptionError`
     */
    func decrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data

}
