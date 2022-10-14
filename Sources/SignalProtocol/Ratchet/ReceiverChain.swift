//
//  ReceiverChain.swift
//  SignalProtocolSwift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A receiver chain is the part of the ratchet that creates the message keys for the received messages.
 */
final class ReceiverChain: ProtocolBufferEquivalent {

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

    /// The receiver chain converted to a protobuf object
    var protoObject: Signal_Session.Chain {
        return Signal_Session.Chain.with {
            $0.senderRatchetKey = ratchetKey.data
            $0.chainKey = chainKey.protoObject
            $0.messageKeys = messageKeys.map { $0.protoObject }
        }
    }

    /**
     Create a receiver chain from a protobuf object.
     - parameter protoObject: The protobuf object
     - throws: `SignaError` of type `invalidProtoBuf`, if data is missing or corrupt.
     */
    init(from protoObject: Signal_Session.Chain) throws {
        self.ratchetKey = try PublicKey(from: protoObject.senderRatchetKey)
        self.chainKey = try RatchetChainKey(from: protoObject.chainKey)
        self.messageKeys = try protoObject.messageKeys.map { try RatchetMessageKeys(from: $0) }
    }
}

// MARK: Protocol Equatable

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
