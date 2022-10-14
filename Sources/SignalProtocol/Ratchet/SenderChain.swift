//
//  SenderChain.swift
//  SignalProtocolSwift
//
//  Created by User on 09.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The sender chain of a ratchet used to encrypt messages for sending.
 */
struct SenderChain {

    /// The key pair of the ratchet
    var ratchetKey: KeyPair

    /// The current chain key of the ratchet
    var chainKey: RatchetChainKey

    /**
     Create a sender chain from the components.
     - parameter ratchetKey: The key pair of the ratchet
     - parameter chainKey: The current chain key of the ratchet
    */
    init(ratchetKey: KeyPair, chainKey: RatchetChainKey) {
        self.ratchetKey = ratchetKey
        self.chainKey = chainKey
    }
}

// MARK: Protocol buffers

extension SenderChain: ProtocolBufferEquivalent {

    /// The sender chain converted to a protobuf object
    var protoObject: Signal_Session.Chain {
        return Signal_Session.Chain.with {
            $0.senderRatchetKey = ratchetKey.publicKey.data
            $0.senderRatchetKeyPrivate = ratchetKey.privateKey.data
            $0.chainKey = chainKey.protoObject
        }
    }

    /**
     Create a sender chain from a protobuf object.
     - parameter protoObject: The protobuf object
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
    */
    init(from protoObject: Signal_Session.Chain) throws {
        guard protoObject.hasChainKey, protoObject.hasSenderRatchetKey, protoObject.hasSenderRatchetKeyPrivate else {
                throw SignalError(.invalidProtoBuf, "Missing data in ProtoBuf object")
        }
        self.chainKey = try RatchetChainKey(from: protoObject.chainKey)
        let publicKey = try PublicKey(from: protoObject.senderRatchetKey)
        let privateKey = try PrivateKey(from: protoObject.senderRatchetKeyPrivate)
        self.ratchetKey = KeyPair(publicKey: publicKey, privateKey: privateKey)
    }
}

// MARK: Protocol Equatable

extension SenderChain: Equatable {
    /**
     Compare two sender chains for equality.
     - parameter lhs: The first chain
     - parameter rhs: The second chain
     - returns: `True`, if the chains are equal
     */
    static func ==(lhs: SenderChain, rhs: SenderChain) -> Bool {
        return lhs.ratchetKey == rhs.ratchetKey && lhs.chainKey == rhs.chainKey
    }
}
