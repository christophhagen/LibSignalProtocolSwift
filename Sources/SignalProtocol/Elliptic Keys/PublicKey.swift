//
//  PublicKey.swift
//  SignalProtocolSwift
//
//  Created by User on 27.01.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation
import Curve25519

/**
 The public part of an elliptic curve key pair.
 The key has a length of `KeyPair.keyLength` byte.
 */
public struct PublicKey {

    /// The base point for the Curve25519 elliptic curve
    private static let basePoint = Data([9] + [UInt8](repeating: 0, count: 31))

    /// The key material of length `KeyPair.keyLength`
    private let key: Data

    /**
     Create a public key from a UInt8 array. Checks
     if length and type are okay.
     - parameter point: The input point as an array
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(point: Data) throws {
        guard point.count == Curve25519.keyLength else {
            throw SignalError(.invalidProtoBuf, "Invalid key length \(point.count)")
        }
        self.key = point
    }

    /**
     Generate a public key from a given private key.
     Fails if the key could not be generated.
     - parameter privateKey: The private key of the pair
     - throws: `SignalError.curveError` if the public key could not be created
     */
    public init(privateKey: PrivateKey) throws {
        do {
            self.key = try Curve25519.publicKey(for: privateKey.data, basepoint: PublicKey.basePoint)
        } catch {
            throw SignalError(.curveError, "Could not create public key from private key: \(error)")
        }
    }

    /**
     Verify that the signature corresponds to the message.
     - parameter signature: The signature data
     - parameter message: The message for which the signature is checked
     - returns: True, if the signature is valid
     */
    public func verify(signature: Data, for message: Data) -> Bool {
        return Curve25519.verify(signature: signature, for: message, publicKey: key)
    }

    /**
     Verify that the vrf signature corresponds to the message.
     - parameter signature: The vrf signature data
     - parameter message: The message for which the signature is checked
     - returns: The vrf output
     - throws: `SignalError.invalidSignature` if the signature is invalid
     */
    func verify(vrfSignature: Data, for message: Data) throws -> Data {
        do {
            return try Curve25519.verify(vrfSignature: vrfSignature, for: message, publicKey: key)
        } catch {
            throw SignalError(.invalidSignature, "Invalid vrf signature: \(error)")
        }
    }

    /**
     Calculate the shared agreement between the given private key and the public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter privateKey: The private key from the other party
     - returns: The agreement data, or `nil` on error
     */
    public func calculateAgreement(privateKey: PrivateKey) throws -> Data {
        do {
          return try Curve25519.calculateAgreement(privateKey: privateKey.data, publicKey: key)
        } catch {
            throw SignalError(.curveError, "Could not calculate curve25519 agreement: \(error)")
        }
    }
}

extension PublicKey: Comparable {

    /**
     Compare two public keys.
     - parameter lhs: The key of the left hand side
     - parameter rhs: The key of the right hand side
     - returns: The comparison result of  first pair of bytes that is not equal, or `false`
     */
    public static func <(lhs: PublicKey, rhs: PublicKey) -> Bool {
        for i in 0..<lhs.key.count {
            if lhs.key[i] != rhs.key[i] {
                return lhs.key[i] < rhs.key[i]
            }
        }
        return false
    }

    /**
     Compare two public keys for equality. The keys are equal if all bytes match.
     - parameter lhs: The key of the left hand side
     - parameter rhs: The key of the right hand side
     - returns: `true`, if the keys are equal
     */
    public static func ==(lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.key == rhs.key
    }

    /// The serialized data of the public key
    public var data: Data {
        return key
    }
}

// MARK: Protocol Buffers

extension PublicKey: ProtocolBufferSerializable {

    /**
     Create a public key from a serialized record.
     - parameter data: The byte record of the object
     - returns: The object
     - throws: `SignalError.invalidProtoBuf`
     */
    public init(from data: Data) throws {
        try self.init(point: data)
    }

    /**
     Return a byte representation of the public key
     - returns: The byte record
     */
    public func protoData() -> Data {
        return data
    }
}
