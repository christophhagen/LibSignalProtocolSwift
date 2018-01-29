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

extension SenderChain {

    /**
     Create a sender chain from a protobuf object.
     - parameter object: The protobuf object
     - parameter version: The kdf version of the chain key
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
    */
    init(from object: Signal_Session.Chain, version: HKDFVersion) throws {
        guard object.hasChainKey, object.hasSenderRatchetKey, object.hasSenderRatchetKeyPrivate else {
                throw SignalError(.invalidProtoBuf, "Missing data in ProtoBuf object")
        }
        self.chainKey = try RatchetChainKey(from: object.chainKey, version: version)
        let publicKey = try PublicKey(from: object.senderRatchetKey)
        let privateKey = try PrivateKey(from: object.senderRatchetKeyPrivate)
        self.ratchetKey = KeyPair(publicKey: publicKey, privateKey: privateKey)
    }

    /**
     Create a sender chain from serialized data.
     - parameter data: The serialized data.
     - parameter version: The kdf version of the chain key
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from data: Data, version: HKDFVersion) throws {
        let object: Signal_Session.Chain
        do {
            object = try Signal_Session.Chain(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create sender chain ProtoBuf object")
        }
        try self.init(from: object, version: version)
    }

    /**
     Convert the sender chain to data.
     - returns: The serialized data.
     - throws: `SignalError` of type `invalidProtoBuf`, if the chain could not be serialized
     */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize sender chain ProtoBuf object")
        }
    }

    /// The sender chain converted to a protobuf object
    var object: Signal_Session.Chain {
        return Signal_Session.Chain.with {
            $0.senderRatchetKey = ratchetKey.publicKey.data
            $0.senderRatchetKeyPrivate = ratchetKey.privateKey.data
            $0.chainKey = chainKey.object
        }
    }
}

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
