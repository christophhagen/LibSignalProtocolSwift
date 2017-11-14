//
//  SignalCommonCrypto.swift
//  libsignal-protocol-swift
//
//  Created by User on 11.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
import CommonCrypto

/**
 Implementation of the `SignalCryptoProvider` protocol using
 CommonCrypto.
 */
struct SignalCommonCrypto: SignalCryptoProvider {

    /**
     Create a number of random bytes
     - parameter bytes: The number of random bytes to create
     - returns: An array of `bytes` length with random numbers
     - throws: `SignalError.noRandomBytes`
     */
    func random(bytes: Int) throws -> [UInt8] {
        let random = [UInt8](repeating: 0, count: bytes)
        let result = SecRandomCopyBytes(nil, bytes, UnsafeMutableRawPointer(mutating: random))

        guard result == errSecSuccess else {
            throw SignalError.noRandomBytes
        }
        return random
    }

    /**
     Create a HMAC authentication for a given message
     - parameter message: The input message to create the HMAC for
     - parameter salt: The salt for the HMAC
     - returns: The HMAC
     */
    func hmacSHA256(for message: [UInt8], with salt: [UInt8]) throws -> [UInt8] {
        var context = CCHmacContext()
        let bytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        withUnsafeMutablePointer(to: &context) { (ptr: UnsafeMutablePointer<CCHmacContext>) in
            CCHmacInit(ptr, CCHmacAlgorithm(kCCHmacAlgSHA256), UnsafeRawPointer(salt), salt.count)
            CCHmacUpdate(ptr, UnsafeRawPointer(message), message.count)
            CCHmacFinal(ptr, UnsafeMutableRawPointer(mutating: bytes))
        }
        return bytes
    }

    /**
     Create a SHA512 digest for a given message
     - parameter message: The input message to create the digest for
     - returns: The digest
     - throws: `SignalError.digestError`
     */
    func sha512(for message: [UInt8]) throws -> [UInt8] {
        var context = CC_SHA512_CTX()
        return try withUnsafeMutablePointer(to: &context) { ptr in
            CC_SHA512_Init(ptr)
            let result = CC_SHA512_Update(ptr, UnsafeRawPointer(message), CC_LONG(message.count))
            guard result == 1 else {
                throw SignalError.digestError
            }
            var md = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            CC_SHA512_Final(&md, ptr)
            return md
        }
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
    func encrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        switch cipher {
        case .AES_CBCwithPKCS5:
            return try process(cbc: message, key: key, iv: iv, encrypt: true)
        case .AES_CTRnoPadding:
            return try encrypt(ctr: message, key: key, iv: iv)
        }
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
    func decrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        switch cipher {
        case .AES_CBCwithPKCS5:
            return try process(cbc: message, key: key, iv: iv, encrypt: false)
        case .AES_CTRnoPadding:
            return try decrypt(ctr: message, key: key, iv: iv)
        }
    }

    /**
     Process (encrypt/decrypt) a message with AES in CBC mode and pkcs7 padding.
     - parameter message: The input message to process
     - parameter key: The key for encryption/decryption (`kCCKeySizeAES128` bytes)
     - parameter iv: The initialization vector
     - parameter encrypt: `true` if encrypting, `false` if decrypting
     - returns: The encrypted/decrypted message
     - throws: `SignalError.encryptionError`, `SignalError.decryptionError`
     */
    func process(cbc message: [UInt8], key: [UInt8], iv: [UInt8], encrypt: Bool) throws -> [UInt8] {
        let operation = encrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt)
        // Create output memory that can fit the output data
        let dataLength = message.count + kCCBlockSizeAES128
        let ptr = UnsafeMutableRawPointer.allocate(bytes: dataLength, alignedTo: MemoryLayout<UInt8>.alignment)
        defer { ptr.deallocate(bytes: dataLength, alignedTo: MemoryLayout<UInt8>.alignment) }

        var dataOutMoved: Int = 0
        let status = CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
            key, key.count, iv, message, message.count, ptr, dataLength, &dataOutMoved)
        guard status == kCCSuccess else {
            throw encrypt ? SignalError.encryptionError : SignalError.decryptionError
        }

        // Convert the pointers to a UInt8 array
        let typedPointer = ptr.bindMemory(to: UInt8.self, capacity: dataOutMoved)
        let typedBuffer = UnsafeMutableBufferPointer(start: typedPointer, count: dataOutMoved)
        let output = Array(typedBuffer)
        return output
    }

    /**
     Encrypt a message with AES in CTR mode and no padding.
     - parameter message: The input message to encrypt
     - parameter key: The key for encryption
     - parameter iv: The initialization vector
     - returns: The encrypted message
     - throws: `SignalError.encryptionError`
     */
    func encrypt(ctr message: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        return try process(ctr: message, key: key, iv: iv, encrypt: true)
    }

    /**
     Decrypt a message with AES in CTR mode and no padding.
     - parameter message: The input message to decrypt
     - parameter key: The key for decryption
     - parameter iv: The initialization vector
     - returns: The decrypted message
     - throws: `SignalError.decryptionError`
     */
    func decrypt(ctr message: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        return try process(ctr: message, key: key, iv: iv, encrypt: false)
    }

    /**
     Process (encrypt/decrypt) a message with AES in CTR mode and no padding.
     - parameter message: The input message to process
     - parameter key: The key for encryption/decryption
     - parameter iv: The initialization vector
     - parameter encrypt: `true` if encrypting, `false` if decrypting
     - returns: The encrypted/decrypted message
     - throws: `SignalError.encryptionError`, `SignalError.decryptionError`
     */
    func process(ctr message: [UInt8], key: [UInt8], iv: [UInt8], encrypt: Bool) throws -> [UInt8] {
        let mode = encrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt)
        var cryptoRef: CCCryptorRef? = nil
        var status = CCCryptorCreateWithMode( mode, CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES),
            CCPadding(ccNoPadding), iv, key, key.count, nil, 0, 0,
            CCModeOptions(kCCModeOptionCTR_BE), &cryptoRef)

        // Release the reference before the method returns or throws an error
        defer { CCCryptorRelease(cryptoRef) }

        guard status == kCCSuccess, let ref = cryptoRef else {
            throw encrypt ? SignalError.encryptionError : SignalError.decryptionError
        }

        let outputLength = CCCryptorGetOutputLength(ref, message.count, true)
        var updateMovedLength = 0
        let ptr = UnsafeMutableRawPointer.allocate(bytes: outputLength, alignedTo: MemoryLayout<UInt8>.alignment)
        // Release the memory before the method returns or throws an error
        defer { ptr.deallocate(bytes: outputLength, alignedTo: MemoryLayout<UInt8>.alignment) }

        status = withUnsafeMutablePointer(to: &updateMovedLength) {
            CCCryptorUpdate(ref, UnsafeRawPointer(message), message.count, ptr, outputLength, $0)
        }

        guard status == kCCSuccess else {
            throw encrypt ? SignalError.encryptionError : SignalError.decryptionError

        }

        let available = outputLength - updateMovedLength
        let ptr2 = ptr.advanced(by: updateMovedLength)
        var finalMovedLength = 0
        status = withUnsafeMutablePointer(to: &finalMovedLength) {
                CCCryptorFinal(ref, ptr2, available, $0)
        }
        let finalLength = updateMovedLength + finalMovedLength
        guard status == kCCSuccess else {
            throw encrypt ? SignalError.encryptionError : SignalError.decryptionError
        }
        // For decryption, the final length can be less due to padding
        if encrypt && finalLength != outputLength {
            throw encrypt ? SignalError.encryptionError : SignalError.decryptionError
        }
        return toArray(from: ptr, count: finalLength)
    }

    /**
     Create an array from an unsafe pointer.
     - parameter ptr: Pointer to initialized storage
     - parameter count: The length of the array
     - returns: The created array
    */
    private func toArray(from ptr: UnsafeMutableRawPointer, count: Int) -> [UInt8] {
        let typedPointer = ptr.bindMemory(to: UInt8.self, capacity: count)
        let typedBuffer = UnsafeMutableBufferPointer(start: typedPointer, count: count)
        return Array(typedBuffer)
    }
}
