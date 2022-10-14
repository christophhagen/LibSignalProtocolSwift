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
struct SessionSignedPreKey {

    /// The public data of the signed pre key
    let publicKey: SessionSignedPreKeyPublic

    /// The private key of the signed pre key
    let privateKey: PrivateKey

    /**
     Create a signed pre key from its components.
     - parameter id: The id of the signed pre key
     - parameter keyPair: The key pair of the signed pre key
     - parameter timestamp: The time when the key was created
     - parameter signature: The signature of the public key of the key pair
     */
    init(id: UInt32, timestamp: UInt64, keyPair: KeyPair, signature: Data) {
        self.publicKey = SessionSignedPreKeyPublic(id: id, timestamp: timestamp, key: keyPair.publicKey, signature: signature)
        self.privateKey = keyPair.privateKey
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
        let keyPair = try KeyPair()
        let signature = try signatureKey.sign(message: keyPair.publicKey.data)
        self.publicKey = SessionSignedPreKeyPublic(id: id, timestamp: timestamp, key: keyPair.publicKey, signature: signature)
        guard publicKey.verify(with: try signatureKey.publicKey()) else {
            throw SignalError(.invalidSignature)
        }
        self.privateKey = keyPair.privateKey
    }

    /// The key pair of the signed pre key
    var keyPair: KeyPair {
        return KeyPair(publicKey: publicKey.key, privateKey: privateKey)
    }
}

// MARK: Protocol Buffers

extension SessionSignedPreKey: ProtocolBufferEquivalent {

    /// Convert the signed pre key to a ProtoBuf object
    var protoObject: Signal_SignedPreKey {
        return Signal_SignedPreKey.with {
            $0.publicKey = self.publicKey.protoObject
            $0.privateKey = self.privateKey.data
        }
    }

    /**
     Create a signed pre key from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    init(from protoObject: Signal_SignedPreKey) throws {
        guard protoObject.hasPublicKey, protoObject.hasPrivateKey else {
                throw SignalError(.invalidProtoBuf, "Missing data in SessionSignedPreKey object")
        }
        self.publicKey = try SessionSignedPreKeyPublic(from: protoObject.publicKey)
        self.privateKey = try PrivateKey(from: protoObject.privateKey)
    }
}

// MARK: Protocol Equatable

extension SessionSignedPreKey: Equatable {

    /**
     Compare two signed pre keys for equality.
     - parameters lhs: The first signed pre key
     - parameters rhs: The second signed pre key
     - returns: `True`, if the signed pre keys match
     */
    static func ==(lhs: SessionSignedPreKey, rhs: SessionSignedPreKey) -> Bool {
        return lhs.privateKey == rhs.privateKey &&
            lhs.publicKey == rhs.publicKey
    }
}
