//
//  SessionPublicSignedPreKey.swift
//  SignalProtocolSwift iOS
//
//  Created by User on 27.01.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation


/**
 A public signed pre key is used as part of a session bundle to establish a new session.
 The public part of the key pair is signed with the identity key of the creator
 to provide authentication.
 */
struct SessionSignedPreKeyPublic {

    /// The id of the signed pre key
    public let id: UInt32

    /// The key pair of the signed pre key
    public let key: PublicKey

    /// The time when the key was created
    public let timestamp: UInt64

    /// The signature of the public key of the key pair
    public let signature: Data

    /**
     Create a public signed pre key from its components.
     - parameter id: The id of the signed pre key
     - parameter key: The public key of the signed pre key
     - parameter timestamp: The time when the key was created
     - parameter signature: The signature of the public key of the key pair
     */
    init(id: UInt32, timestamp: UInt64, key: PublicKey, signature: Data) {
        self.id = id
        self.key = key
        self.timestamp = timestamp
        self.signature = signature
    }
    
    /**
     Verify that the signed key is valid.
     - parameter: The public key of the user who signed the key
     - returns: `true` if the signature is valid
     */
    func verify(with publicKey: PublicKey) -> Bool {
        return publicKey.verify(signature: signature, for: key.data)
    }
}

// MARK: Protocol Buffers

extension SessionSignedPreKeyPublic: ProtocolBufferEquivalent {

    /// Convert the public signed pre key to a ProtoBuf object
    var protoObject: Signal_SignedPreKey.PublicPart {
        return Signal_SignedPreKey.PublicPart.with {
            $0.id = self.id
            $0.key = self.key.data
            $0.timestamp = self.timestamp
            $0.signature = self.signature
        }
    }

    /**
     Create a signed pre key from a ProtoBuf object.
     - parameter protoObject: The ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    init(from protoObject: Signal_SignedPreKey.PublicPart) throws {
        guard protoObject.hasID, protoObject.hasKey,
            protoObject.hasSignature, protoObject.hasTimestamp else {
                throw SignalError(.invalidProtoBuf, "Missing data in SessionSignedPreKey object")
        }
        self.id = protoObject.id
        self.key = try PublicKey(from: protoObject.key)
        self.timestamp = protoObject.timestamp
        self.signature = protoObject.signature
    }
}

// MARK: Protocol Equatable

extension SessionSignedPreKeyPublic: Equatable {

    /**
     Compare two public signed pre keys for equality.
     - parameters lhs: The first public signed pre key
     - parameters rhs: The second public signed pre key
     - returns: `True`, if the public signed pre keys match
     */
    static func ==(lhs: SessionSignedPreKeyPublic, rhs: SessionSignedPreKeyPublic) -> Bool {
        return lhs.id == rhs.id &&
            lhs.key == rhs.key &&
            lhs.signature == rhs.signature &&
            lhs.timestamp == rhs.timestamp
    }
}
