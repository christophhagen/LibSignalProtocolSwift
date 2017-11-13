//
//  PrivateKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 11.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The private part of an elliptic curve key pair.
 The key has a length of `KeyPair.keyLength` byte.
 */
public struct PrivateKey {

    /// The key material of length `KeyPair.keyLength`
    internal let key: [UInt8]

    /**
     Create a private key. Only checks the length, nothing else.
     - parameter point: The private key data
     - returns: The key
     - throws: `SignalError.invalidLength`
     */
    init(point: [UInt8]) throws {
        guard point.count == KeyPair.keyLength else {
            signalLog(level: .error, "Invalid key length: \(point.count)")
           throw SignalError.invalidProtoBuf
        }
//        guard point[0] & 0b00000111 == 0 else {
//            print("Invalid: \(point[0])")
//            throw SignalError.invalidProtoBuf
//        }
//        guard point[31] & 0b10000000 == 0 else {
//            print("Invalid: \(point[0])")
//            throw SignalError.invalidProtoBuf
//        }
//        guard point[31] & 0b01000000 != 0 else {
//            print("Invalid: \(point[0])")
//            throw SignalError.invalidProtoBuf
//        }
        key = point
    }

    /**
     Create a new random private key.
     - throws: Any error from `signalCryptoRandom(bytes:)`
     */
    public init() throws {
        var random = try SignalCrypto.random(bytes: KeyPair.keyLength)
        random[0] &= 248 // 0b11111000
        random[31] = (random[31] & 127) | 64 // & 0b01111111 | 0b01000000
        self.key = random
    }

    /**
     Calculate the signature for the given message.
     - parameter message: The message to sign
     - returns: The signature of the message
     - throws: SignalError
     */
    func sign(message: Data) throws -> Data {
        guard message.count < 256 else {
            signalLog(level: .error, "Could not sign message, too long: \(message.count)")
            throw SignalError.invalidSignature
        }
        let random = try SignalCrypto.random(bytes: KeyPair.signatureLength)
        var signature = [UInt8](repeating: 0, count: KeyPair.signatureLength)

        let length = message.count
        guard length > 0 else {
            signalLog(level: .error, "Invalid length \(length)")
            throw SignalError.invalidSignature
        }
        let result = curve25519_sign(&signature, key, [UInt8](message), UInt(length), random)
        guard result == 0 else {
            signalLog(level: .error, "Could not sign message: \(result), count \(message.count)")
            throw SignalError.invalidSignature
        }
        return Data(signature)
    }

    /**
     Calculates a unique Curve25519 signature for the private key
     - parameter message: The message to sign
     - returns: The 96-byte signature on success
     - throws: `SignalError`
     */
    func signVRF(message: Data) throws -> Data {
        let random = try SignalCrypto.random(bytes: 64)

        var signature = [UInt8](repeating: 0, count: KeyPair.vrfSignatureLength)

        let result = generalized_xveddsa_25519_sign(&signature, key, [UInt8](message), UInt(message.count), random, nil, 0)
        guard result == 0 else {
            signalLog(level: .error, "Signature failed \(result)")
            throw SignalError.invalidSignature
        }
        return Data(signature)
    }

    /**
     Calculate the shared agreement between the private key and the given public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter publicKey: The public key from the other party
     - returns: The agreement data, or `nil` on error
     */
    func calculateAgreement(publicKey: PublicKey) throws -> [UInt8] {
        return try publicKey.calculateAgreement(privateKey: self)
    }
}

extension PrivateKey {
    
    /**
     Create a private key from a byte record.
     - parameter data: The byte record
     - returns: The private key
     - throws: `SignalError.invalidProtoBuf`
    */
    init(from data: Data) throws {
        try self.init(point: [UInt8](data))
    }
    
    var data: Data {
        return Data(key)
    }
    
    var array: [UInt8] {
        return key
    }
    
}

extension PrivateKey: Equatable {
    public static func ==(lhs: PrivateKey, rhs: PrivateKey) -> Bool {
        return lhs.key == rhs.key
    }


}
