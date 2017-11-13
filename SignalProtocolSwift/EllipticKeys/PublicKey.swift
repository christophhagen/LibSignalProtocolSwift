//
//  PublicKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 11.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The public part of an elliptic curve key pair.
 The key has a length of `KeyPair.keyLength` byte.
 */
struct PublicKey {
    
    /// The base point for the Curve25519 elliptic curve
    private static let basePoint = [9] + [UInt8](repeating: 0, count: 31)

    /// The key material of length `KeyPair.keyLength`
    internal let key: [UInt8]

    /**
     'Create a public key from a UInt8 array. Checks
     if length and type are okay.
     - parameter point: The input point as an array
     - returns: The key, if valid, or `nil`
     */
    init(point: [UInt8]) throws {
        guard point.count == KeyPair.keyLength + 1 else {
            signalLog(level: .error, "Invalid key length \(point.count)")
            throw SignalError.invalidProtoBuf
        }

        guard point[0] == KeyPair.DJBType else {
            signalLog(level: .error, "Invalid key type: \(point[0])")
            throw SignalError.invalidProtoBuf
        }
        key = Array(point[1..<point.count])
    }

    /**
     Generate a public key from a given private key.
     Fails if the key could not be generated.
     - parameter privateKey: The private key of the pair
     - returns: The public key
     - throws `SignalError.curveError` if the public key could not be created
     */
    init(privateKey: PrivateKey) throws {
        var key = [UInt8](repeating: 0, count: KeyPair.keyLength)
        guard curve25519_donna(&key, privateKey.key, PublicKey.basePoint) == 0 else {
            signalLog(level: .error, "Could not create public key from private key")
            throw SignalError.curveError
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
            signalLog(level: .info, "Wrong signature length \(signature.count)")
            return false
        }
        guard key.count == KeyPair.keyLength else {
            signalLog(level: .info, "Wrong key length \(key.count)")
            return false
        }
        let sig = [UInt8](signature)
        return curve25519_verify(sig, key, [UInt8](message), UInt(message.count)) == 0
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
            signalLog(level: .error, "Invalid vrf signature length \(vrfSignature.count)")
            throw SignalError.invalidLength
        }

        var vrfOutput = [UInt8](repeating: 0, count: KeyPair.vrfVerifyLength)
        let result = generalized_xveddsa_25519_verify(&vrfOutput, [UInt8](vrfSignature), key, [UInt8](message), UInt(message.count), nil, 0)
        guard result == 0 else {
            signalLog(level: .error, "Invalid vrf signature \(result)")
            throw SignalError.invalidSignature
        }
        return Data(vrfOutput)
    }

    /**
     Calculate the shared agreement between the given private key and the public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter privateKey: The private key from the other party
     - returns: The agreement data, or `nil` on error
     */
    func calculateAgreement(privateKey: PrivateKey) throws -> [UInt8] {
        var sharedKey = [UInt8](repeating: 0, count: KeyPair.keyLength)
        guard curve25519_donna(&sharedKey, privateKey.key, key) == 0 else {
            signalLog(level: .error, "Could not calculate curve25519 agreement")
            throw SignalError.curveError
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
    static func <(lhs: PublicKey, rhs: PublicKey) -> Bool {
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
    static func ==(lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.key == rhs.key
    }
}

extension PublicKey {

    /**
     Create a public key from a serialized record.
     - note
     - parameter data: The byte record of the object
     - returns: The object
     - throws: `SignalError.invalidProtoBuf`
     */
    init(from data: Data) throws {
        try self.init(point: [UInt8](data))
    }

    /**
     Return a byte representation of the public key
     - returns: The byte record
     */
    var data: Data {
        return Data(array)
    }
    
    var array: [UInt8] {
        return [KeyPair.DJBType] + key
    }
}
