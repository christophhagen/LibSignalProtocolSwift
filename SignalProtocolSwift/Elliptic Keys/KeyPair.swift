//
//  KeyPair.swift
//  SignalProtocolSwift
//
//  Created by User on 27.01.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation


/**
 A pair of public and private key for elliptic curve cryptopgraphy
 */
public struct KeyPair {

    /// Type declaration (only needed for compatibility)
    static let DJBType: UInt8 = 0x05

    
    /// The public part of the key pair
    public let publicKey: PublicKey

    /// The private part of the key pair
    public let privateKey: PrivateKey

    // MARK: Initialization

    /**
     Create a key pair from existing public and private keys
     - parameter publicKey: The public part of the key pair
     - parameter privateKey: The private part of the key pair
     */
    public init(publicKey: PublicKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    /**
     Create a new random key pair.
     - returns: A new randomly created key pair
     - throws: `SignalError` errors:
     `noRandomBytes` if the crypto provider can't provide random bytes.
     `curveError` if no public key could be created from the random private key.
     */
    public init() throws {
        let newPrivateKey = try PrivateKey()
        let newPublicKey = try PublicKey(privateKey: newPrivateKey)
        self.privateKey = newPrivateKey
        self.publicKey = newPublicKey
    }

    // MARK: Exposed private key functions

    /**
     Calculate the signature for the given message.
     - parameter message: The message to sign
     - returns: The signature of the message, `KeyPair.signatureLength` bytes
     - throws: `SignalError` errors:
     `invalidLength`, if the message is more than 256 or 0 byte.
     `invalidSignature`, if the message could not be signed.
     `noRandomBytes`, if the crypto provider could not provide random bytes.
     */
    func sign(message: Data) throws -> Data {
        return try privateKey.sign(message: message)
    }

    /**
     Calculates a unique Curve25519 signature for the private key
     - parameter message: The message to sign
     - returns: The 96-byte signature on success
     - throws: `SignalError`
     */
    func signVRF(message: Data) throws -> Data {
        return try privateKey.signVRF(message: message)
    }

    /**
     Calculate the shared agreement between the private key and the given public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter publicKey: The public key from the other party
     - returns: The agreement data, or `nil` on error
     */
    func calculateAgreement(publicKey: PublicKey) throws -> Data {
        return try publicKey.calculateAgreement(privateKey: privateKey)
    }

    // MARK: Exposed public key functions

    /**
     Verify that the signature corresponds to the message.
     - parameter signature: The signature data
     - parameter message: The message for which the signature is checked
     - returns: True, if the signature is valid
     */
    func verify(signature: Data, for message: Data) -> Bool {
        return publicKey.verify(signature: signature, for: message)
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
        return try publicKey.verify(vrfSignature: vrfSignature, for: message)
    }

    /**
     Calculate the shared agreement between the given private key and the public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter privateKey: The private key from the other party
     - returns: The agreement data, or `nil` on error
     */
    func calculateAgreement(privateKey: PrivateKey) throws -> Data {
        return try publicKey.calculateAgreement(privateKey: privateKey)
    }
}

// MARK: Protocol Buffers

/**
 Provide the possibility to convert a `KeyPair` from and to bytes
 */
extension KeyPair {

    /**
     Create a key pair from a serialized record.
     - parameter data: The serialized key pair.
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(from data: Data) throws {
        let object: Textsecure_IdentityKeyPairStructure
        do {
            object = try Textsecure_IdentityKeyPairStructure(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create key pair from data: \(error)")
        }
        try self.init(from: object)
    }

    /**
     Create a key pair from a protobuf object.
     - parameter object: The protobuf object.
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(from object: Textsecure_IdentityKeyPairStructure) throws {
        guard object.hasPublicKey, object.hasPrivateKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in KeyPair ProtoBuf object")
        }
        self.publicKey = try PublicKey(from: object.publicKey)
        self.privateKey = try PrivateKey(from: object.privateKey)
    }

    /// The key pair converted to a ProtoBuf object
    var object: Textsecure_IdentityKeyPairStructure {
        return Textsecure_IdentityKeyPairStructure.with {
            $0.publicKey = self.publicKey.data
            $0.privateKey = self.privateKey.data
        }
    }

    /**
     Return a serialized record of the key pair
     - returns: The serialized record
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize KeyPair: \(error)")
        }
    }
}

// MARK: Protocol Equatable

extension KeyPair: Equatable {

    /**
     Compare two key pairs for equality. The keys are equal if public and private keys match.
     - parameter lhs: The key pair of the left hand side
     - parameter rhs: The key pair of the right hand side
     - returns: `true`, if the keys are equal
     */
    public static func ==(lhs: KeyPair, rhs: KeyPair) -> Bool {
        return lhs.privateKey == rhs.privateKey && lhs.publicKey == rhs.publicKey
    }
}

