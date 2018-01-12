//
//  ReceiverChain.swift
//  libsignal-protocol-swift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A receiver chain is the part of the ratchet that creates the message keys for the received messages.
 */
final class ReceiverChain {

    /// The current ratchet key
    var ratchetKey: PublicKey

    /// The current chain key
    var chainKey: RatchetChainKey

    /// The stored message keys for out-of-order messages
    private var messageKeys = [RatchetMessageKeys]()

    /**
     Create a receiver chain from the components.
     - parameter ratchetKey: The current ratchet key
     - parameter chainKey: The current chain key
    */
    init(ratchetKey: PublicKey, chainKey: RatchetChainKey) {
        self.ratchetKey = ratchetKey
        self.chainKey = chainKey
    }

    /**
     Add a message key to the stored message keys.
     - parameter messageKey: The keys to add
    */
    func add(messageKey: RatchetMessageKeys) {
        // Replace new keys if the counter already exists
        for index in 0..<messageKeys.count {
            if messageKeys[index].counter == messageKey.counter {
                messageKeys[index] = messageKey
                return
            }
        }
        messageKeys.insert(messageKey, at: 0)
        // Delete old keys
        if messageKeys.count > SenderKeyState.messageKeyMaximum {
            messageKeys.removeLast(messageKeys.count - SenderKeyState.messageKeyMaximum)
        }
    }

    /**
     Check if a message key already exists.
     - parameter messageKey: The keys to check
     - returns: `True`, if a key already exists for the counter
    */
    func has(messageKey: RatchetMessageKeys) -> Bool {
        for item in messageKeys {
            if item.counter == messageKey.counter {
                return true
            }
        }
        return false
    }

    /**
     Get a message key if it exists.
     - parameter iteration: The counter for which to get the keys
     - returns: The message keys, if they exist
     */
    func messageKey(for iteration: UInt32) -> RatchetMessageKeys? {
        for item in messageKeys {
            if item.counter == iteration {
                return item
            }
        }
        return nil
    }

    /**
     Remove a message key and return it.
     - parameter iteration: The counter for which to remove the keys
     - returns: The message keys, if they exist
     */
    func removeMessageKey(for iteration: UInt32) -> RatchetMessageKeys? {
        for index in 0..<messageKeys.count {
            if messageKeys[index].counter == iteration {
                return messageKeys.remove(at: index)
            }
        }
        return nil
    }
    
    // MARK: Protocol Buffers
    
    init(from object: Textsecure_SessionStructure.Chain, version: HKDFVersion) throws {
        self.ratchetKey = try PublicKey(from: object.senderRatchetKey)
        self.chainKey = try RatchetChainKey(from: object.chainKey, version: version)
        self.messageKeys = try object.messageKeys.map { try RatchetMessageKeys(from: $0) }
    }

    /**
     Deserialize a receiver chain.
     - parameter data: The serialized chain.
     - parameter version: The KDF version of the chain key.
     - throws: `SignaError` of type `invalidProtoBuf`, if data is missing or corrupt.
     */
    convenience init(from data: Data, version: HKDFVersion) throws {
        let object: Textsecure_SessionStructure.Chain
        do {
            object = try Textsecure_SessionStructure.Chain(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create ReceiverChain protobuf object: \(error)")
        }
        try self.init(from: object, version: version)
    }

    /**
     Serialize the receiver chain.
     - returns: The serialized chain.
     - throws:
    */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize receiver chain: \(error)")
        }
    }

    /// The receiver chain converted to a protobuf object
    var object: Textsecure_SessionStructure.Chain {
        return Textsecure_SessionStructure.Chain.with {
            $0.senderRatchetKey = ratchetKey.data
            $0.chainKey = chainKey.object
            $0.messageKeys = messageKeys.map { $0.object }
        }
    }
}

extension ReceiverChain: Equatable {
    /**
     Compare two receiver chains for equality.
     - parameter lhs: The first chain
     - parameter rhs: The second chain
     - returns: `True`, if the chains are equal
     */
    static func ==(lhs: ReceiverChain, rhs: ReceiverChain) -> Bool {
        return lhs.ratchetKey == rhs.ratchetKey &&
            lhs.chainKey == rhs.chainKey &&
            lhs.messageKeys == rhs.messageKeys
    }
}
