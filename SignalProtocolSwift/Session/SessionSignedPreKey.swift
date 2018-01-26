//
//  SessionSignedPreKey.swift
//  SignalProtocolSwift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A signed pre key is used as part of a session bundle to establish a new session.
 The public part of the key pair is signed with the identity key of the creator
 to provide authentication.
 */
public struct SessionSignedPreKey {

    /// The id of the signed pre key
    public let id: UInt32

    /// The key pair of the signed pre key
    public let keyPair: KeyPair

    /// The time when the key was created
    public let timestamp: UInt64

    /// The signature of the public key of the key pair
    public let signature: Data

    /**
     Create a signed pre key from its components.
     - parameter id: The id of the signed pre key
     - parameter keyPair: The key pair of the signed pre key
     - parameter timestamp: The time when the key was created
     - parameter signature: The signature of the public key of the key pair
     */
    init(id: UInt32, timestamp: UInt64, keyPair: KeyPair, signature: Data) {
        self.id = id
        self.keyPair = keyPair
        self.timestamp = timestamp
        self.signature = signature
    }

    /**
     Create a signed pre key.
     - note: The following errors can be thrown:
     - `noRandomBytes`, if the crypto provider can't provide random bytes.
     - `curveError`, if no public key could be created from the random private key.
     - `invalidLength`, if the public key is more than 256 or 0 byte.
     - `invalidSignature`, if the message could not be signed.
     - parameter id: The id of the signed pre key
     - parameter keyPair: The key pair of the signed pre key
     - parameter timestamp: The time when the key was created
     - parameter signature: The signature of the public key of the key pair
     */
    init(id: UInt32, signatureKey: PrivateKey, timestamp: UInt64) throws {
        self.id = id
        self.keyPair = try KeyPair()
        self.timestamp = timestamp
        self.signature = try signatureKey.sign(message: self.keyPair.publicKey.data)
    }
}

// MARK: Protocol Buffers

extension SessionSignedPreKey {

    /**
     Create a signed pre key from serialized data.
     - parameter data: The serialized record.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    public init(from data: Data) throws {
        let object: Textsecure_SignedPreKeyRecordStructure
        do {
            object = try Textsecure_SignedPreKeyRecordStructure(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not deserialize SessionSignedPreKey ProtoBuf object: \(error)")
        }
        try self.init(from: object)
    }

    /**
     Create a signed pre key from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    init(from object: Textsecure_SignedPreKeyRecordStructure) throws {
        guard object.hasID, object.hasPublicKey, object.hasPrivateKey,
            object.hasSignature, object.hasTimestamp else {
                throw SignalError(.invalidProtoBuf, "Missing data in SessionSignedPreKey object")
        }
        self.id = object.id
        self.keyPair = KeyPair(
            publicKey: try PublicKey(from: object.publicKey),
            privateKey: try PrivateKey(from: object.privateKey))
        self.timestamp = object.timestamp
        self.signature = object.signature
    }

    /// Convert the signed pre key to a ProtoBuf object
    var object: Textsecure_SignedPreKeyRecordStructure {
        return Textsecure_SignedPreKeyRecordStructure.with {
            $0.id = self.id
            $0.publicKey = self.keyPair.publicKey.data
            $0.privateKey = self.keyPair.privateKey.data
            $0.timestamp = self.timestamp
            $0.signature = self.signature
        }
    }

    /**
     Convert the signed pre key to serialized data.
     - returns: The serialized record.
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SessionSignedPreKey ProtoBuf object: \(error)")
        }
    }
}

extension SessionSignedPreKey: Equatable {

    /**
     Compare two signed pre keys for equality.
     - parameters lhs: The first signed pre key
     - parameters rhs: The second signed pre key
     - returns: `True`, if the signed pre keys match
     */
    public static func ==(lhs: SessionSignedPreKey, rhs: SessionSignedPreKey) -> Bool {
        return lhs.id == rhs.id &&
            lhs.keyPair == rhs.keyPair &&
            lhs.signature == rhs.signature &&
            lhs.timestamp == rhs.timestamp
    }
}
