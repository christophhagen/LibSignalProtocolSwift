//
//  SessionPreKey.swift
//  SignalProtocolSwift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A pre key used to esatblish a session. A unique pre key is used for
 each new session.
 */
struct SessionPreKey {

    /// The upper bound (inclusive) of the pre key id
    static let mediumMaxValue: UInt32 = 0xFFFFFF

    /// The public data of the pre key (id and public key)
    let publicKey: SessionPreKeyPublic

    /// The private key of the pre key
    let privateKey: PrivateKey

    /**
     Create a pre key from the components
     - parameter id: The pre key id
     - parameter keyPair: The key pair of the pre key
    */
    init(id: UInt32, keyPair: KeyPair) {
        self.publicKey = SessionPreKeyPublic(id: id, key: keyPair.publicKey)
        self.privateKey = keyPair.privateKey
    }

    /**
     Create a new pre key with the index.
     - note: Possible errors:
     - `curveError` if the public key could not be created.
     - `noRandomBytes`, if the crypto delegate could not provide random data
     - parameter index: The index to create the id
     - throws: `SignalError` errors
    */
    init(index: UInt32) throws {
        let id = index
        let keyPair = try KeyPair()
        self.init(id: id, keyPair: keyPair)
    }

    /// The key pair of the signed pre key
    var keyPair: KeyPair {
        return KeyPair(publicKey: publicKey.key, privateKey: privateKey)
    }
}

// MARK: Protocol Buffers

extension SessionPreKey: ProtocolBufferEquivalent {

    /// Convert the pre key to a ProtoBuf object
    var protoObject: Signal_PreKey {
        return Signal_PreKey.with {
            $0.publicKey = publicKey.protoObject
            $0.privateKey = privateKey.data
        }
    }

    /**
     Create a pre key from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    init(from object: Signal_PreKey) throws {
        guard object.hasPublicKey, object.hasPrivateKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SessionPreKey object")
        }
        self.publicKey = try SessionPreKeyPublic(from: object.publicKey)
        self.privateKey = try PrivateKey(from: object.privateKey)
    }
}
