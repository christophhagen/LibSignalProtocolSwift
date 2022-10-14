//
//  PrivateKey.swift
//  SignalProtocolSwift
//
//  Created by User on 27.01.18.
//  Copyright © 2018 User. All rights reserved.
//
import Foundation
import Curve25519

/**
 The private part of an elliptic curve key pair.
 The key has a length of `KeyPair.keyLength` byte.
 */
public struct PrivateKey {

    /// The key material of length `KeyPair.keyLength`
    private let key: Data

    /**
     Create a private key from a curve point.
     - parameter point: The private key data
     - returns: The key
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(point: Data) throws {
        guard point.count == Curve25519.keyLength else {
            throw SignalError(.invalidProtoBuf, "Invalid key length: \(point.count)")
        }
        guard point[0] & 0b00000111 == 0 else {
            throw SignalError(.invalidProtoBuf, "Invalid private key (byte 0 == \(point[0])")
        }

        let lastByteIndex = Curve25519.keyLength - 1
        guard point[lastByteIndex] & 0b10000000 == 0 else {
            throw SignalError(.invalidProtoBuf, "Invalid private key (byte \(lastByteIndex) == \(point[lastByteIndex])")
        }
        guard point[lastByteIndex] & 0b01000000 != 0 else {
            throw SignalError(.invalidProtoBuf, "Invalid private key (byte \(lastByteIndex) == \(point[lastByteIndex])")
        }
        key = point
    }

    /**
     Create a private key. Only checks the length, nothing else.
     - note: Possible errors are:
     - `invalidLength`, if the data has the wrong length
     - parameter point: The private key data
     - returns: The key
     - throws: `SignalError` errors
     */
    init(unverifiedPoint point: Data) throws {
        guard point.count == Curve25519.keyLength else {
            throw SignalError(.invalidLength, "Invalid key length: \(point.count)")
        }
        key = point
    }

    /**
     Create a new random private key.
     - throws: Any error from `SignalCrypto.random(bytes:)`
     */
    public init() throws {
        var random = try SignalCrypto.random(bytes: Curve25519.keyLength)
        random[0] &= 248 // 0b11111000
        random[31] = (random[31] & 127) | 64 // & 0b01111111 | 0b01000000
        self.key = random
    }

    /**
     Calculate the signature for the given message.
     - parameter message: The message to sign
     - returns: The signature of the message, `KeyPair.signatureLength` bytes
     - throws: `SignalError` errors:
     `invalidSignature`, if the message could not be signed.
     `noRandomBytes`, if the crypto provider could not provide random bytes.
     */
    public func sign(message: Data) throws -> Data {
        let random = try SignalCrypto.random(bytes: Curve25519.signatureLength)

        do {
            return try Curve25519.signature(for: message, privateKey: key, randomData: random)
        } catch {
            throw SignalError(.invalidSignature, "Could not sign message: \(error)")
        }
    }

    /**
     Calculates a unique Curve25519 signature for the private key
     - parameter message: The message to sign
     - returns: The 96-byte signature on success
     - throws: `SignalError`
     */
    func signVRF(message: Data) throws -> Data {
        let random = try SignalCrypto.random(bytes: 32)

        do {
            return try Curve25519.vrfSignature(for: message, privateKey: key, randomData: random)
        } catch {
            throw SignalError(.invalidSignature, "VRF signature failed: \(error)")
        }
    }

    /**
     Calculate the shared agreement between the private key and the given public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter publicKey: The public key from the other party
     - returns: The agreement data, or `nil` on error
     */
    public func calculateAgreement(publicKey: PublicKey) throws -> Data {
        return try publicKey.calculateAgreement(privateKey: self)
    }

    /// The serialized data of the private key
    var data: Data {
        return key
    }
    
    /**
     Create the corresponding key pair for the private key
     - throws `SignalError.curveError` if the public key could not be created
     */
    func keyPair() throws -> KeyPair {
        return try KeyPair(privateKey: self)
    }
    
    /**
     Create the corresponding public key for the private key
     - throws `SignalError.curveError` if the public key could not be created
     */
    func publicKey() throws -> PublicKey {
        return try PublicKey(privateKey: self)
    }
}

extension PrivateKey: Equatable {
    /**
     Compare two private keys for equality.
     - parameter lhs: The first key.
     - parameter rhs: The second key.
     - returns: `True`, if the keys are equal
     */
    public static func ==(lhs: PrivateKey, rhs: PrivateKey) -> Bool {
        return lhs.key == rhs.key
    }
}

// MARK: Protocol Buffers

extension PrivateKey: ProtocolBufferSerializable {

    /**
     Create a private key from a byte record.
     - parameter data: The byte record
     - returns: The private key
     - throws: `SignalError.invalidProtoBuf`
     */
    public init(from data: Data) throws {
        try self.init(point: data)
    }

    /// Convert the key to serialized data
    public func protoData() -> Data {
        return key
    }
}
