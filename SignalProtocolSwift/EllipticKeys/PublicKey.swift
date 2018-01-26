//
//  PublicKey.swift
//  SignalProtocolSwift
//
//  Created by User on 11.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The public part of an elliptic curve key pair.
 The key has a length of `KeyPair.keyLength` byte.
 */
public struct PublicKey {
    
    /// The base point for the Curve25519 elliptic curve
    private static let basePoint = [9] + [UInt8](repeating: 0, count: 31)

    /// The key material of length `KeyPair.keyLength`
    private let key: Data

    /**
     'Create a public key from a UInt8 array. Checks
     if length and type are okay.
     - parameter point: The input point as an array
     - returns: The key, if valid, or `nil`
     */
    init(point: Data) throws {
        guard point.count == KeyPair.keyLength + 1 else {
            throw SignalError(.invalidProtoBuf, "Invalid key length \(point.count)")
        }

        guard point[0] == KeyPair.DJBType else {
            throw SignalError(.invalidProtoBuf, "Invalid key type: \(point[0])")
        }
        key = point.advanced(by: 1)
    }

    /**
     Generate a public key from a given private key.
     Fails if the key could not be generated.
     - parameter privateKey: The private key of the pair
     - returns: The public key
     - throws `SignalError.curveError` if the public key could not be created
     */
    public init(privateKey: PrivateKey) throws {
        var key = Data(count: KeyPair.keyLength)
        let result: Int32 = key.withUnsafeMutableBytes { keyPtr in
            privateKey.data.withUnsafeBytes {
                curve25519_donna(keyPtr, $0, PublicKey.basePoint)
            }
        }
        guard result == 0 else {
            throw SignalError(.curveError, "Could not create public key from private key: \(result)")
        }
        self.key = key
    }

    /**
     Verify that the signature corresponds to the message.
     - parameter signature: The signature data
     - parameter message: The message for which the signature is checked
     - returns: True, if the signature is valid
     */
    func verify(signature: Data, for message: Data) -> Bool {
        guard signature.count == KeyPair.signatureLength else {
            return false
        }
        guard key.count == KeyPair.keyLength else {
            return false
        }
        let result = signature.withUnsafeBytes { signaturePtr in
            key.withUnsafeBytes { keyPtr in
                message.withUnsafeBytes { messagePtr in
                    curve25519_verify(signaturePtr, keyPtr, messagePtr, UInt(message.count))
                }
            }
        }
        return result == 0
    }

    /**
     Verify that the vrf signature corresponds to the message.
     - parameter signature: The vrf signature data
     - parameter message: The message for which the signature is checked
     - returns: The vrf output
     - throws: `SignalError.invalidLength` if the signature has the wrong length,
     `SignalError.invalidSignature` if the signature is invalid
     */
    func verify(vrfSignature: Data, for message: Data) throws -> Data {
        guard vrfSignature.count == KeyPair.vrfSignatureLength else {
            throw SignalError(.invalidLength, "Invalid vrf signature length \(vrfSignature.count)")
        }

        var output = Data(count: KeyPair.vrfVerifyLength)
        let result = key.withUnsafeBytes { keyPtr in
            message.withUnsafeBytes { messagePtr in
                vrfSignature.withUnsafeBytes { vrfPtr in
                    output.withUnsafeMutableBytes { outputPtr in
                        generalized_xveddsa_25519_verify(outputPtr, vrfPtr, keyPtr, messagePtr, UInt(message.count), nil, 0)
                    }
                }
            }
        }
        guard result == 0 else {
            throw SignalError(.invalidSignature,  "Invalid vrf signature \(result)")
        }
        return output
    }

    /**
     Calculate the shared agreement between the given private key and the public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter privateKey: The private key from the other party
     - returns: The agreement data, or `nil` on error
     */
    func calculateAgreement(privateKey: PrivateKey) throws -> Data {
        var sharedKey = Data(count: KeyPair.keyLength)
        let result: Int32 = sharedKey.withUnsafeMutableBytes { sharedKeyPtr in
            privateKey.data.withUnsafeBytes { dataPtr in
                key.withUnsafeBytes { keyPtr in
                    curve25519_donna(sharedKeyPtr, dataPtr, keyPtr)
                }
            }
        }
        guard result == 0 else {
            throw SignalError(.curveError, "Could not calculate curve25519 agreement")
        }
        return sharedKey
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
}

// MARK: Protocol Buffers

extension PublicKey {

    /**
     Create a public key from a serialized record.
     - parameter data: The byte record of the object
     - returns: The object
     - throws: `SignalError.invalidProtoBuf`
     */
    init(from data: Data) throws {
        try self.init(point: data)
    }

    /**
     Return a byte representation of the public key
     - returns: The byte record
     */
    var data: Data {
        return Data([KeyPair.DJBType]) + key
    }
}
