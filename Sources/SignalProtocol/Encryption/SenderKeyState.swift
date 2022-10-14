//
//  SenderKeyState.swift
//  SignalProtocolSwift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A state of a group message session with a recipient,
 which saves the message keys of out-of-order messages
 and generates new keys for messages.
 Each session can have multiple states.
 */
final class SenderKeyState: ProtocolBufferEquivalent {

    /// The maximum number of message keys stored
    static let messageKeyMaximum = 2000

    /// The current key id
    var keyId: UInt32

    /// The chain key of the state used for key generation
    var chainKey: SenderChainKey

    /// The signature key
    var signaturePublicKey: PublicKey

    /// The private part of the signature key, optional
    var signaturePrivateKey: PrivateKey?

    /// Dictionary of message keys indexed by iteration
    private var messageKeys: [SenderMessageKey]

    /**
     Create a new session state.
     - parameter keyId: The id of the current key
     - parameter chainKey: The current sender chain key of the state.
     - parameter signaturePublicKey: The public key used for message verification
     - parameter signaturePrivateKey: The optional private key used for message signing
    */
    init(keyId: UInt32,
         chainKey: SenderChainKey,
         signaturePublicKey: PublicKey,
         signaturePrivateKey: PrivateKey?) {
        self.keyId = keyId
        self.chainKey = chainKey
        self.signaturePublicKey = signaturePublicKey
        self.signaturePrivateKey = signaturePrivateKey
        self.messageKeys = [SenderMessageKey]()
    }

    /**
     Add a `SenderMessageKey` to the keys which are stored to decrypt old (out of order) messages.
     - parameter messageKey: The keys to add
     - parameter removingOldKeys: Set to true, if old keys should be deleted if the maximum key number is reached.
    */
    func add(messageKey: SenderMessageKey, removingOldKeys: Bool = true) {
        messageKeys.insert(messageKey, at: 0)
        if removingOldKeys && messageKeys.count > SenderKeyState.messageKeyMaximum {
            messageKeys.removeLast(messageKeys.count - SenderKeyState.messageKeyMaximum)
        }
    }

    /**
     Get the message key for the iteration, if it exists.
     - parameter iteration: The iteration of the key
     - returns: The key for the iteration, or nil
    */
    func messageKey(for iteration: UInt32) -> SenderMessageKey? {
        for index in 0..<messageKeys.count {
            if messageKeys[index].iteration == iteration {
                return messageKeys.remove(at: index)
            }
        }
        return nil
    }

    /**
     Remove old message keys if the number is higher then the maximum.
    */
    private func removeOldMessageKeys() {
        let count = messageKeys.count - SenderKeyState.messageKeyMaximum
        if count > 0 {
            messageKeys.removeLast(count)
        }
    }

    /**
     Get the sender key for the iteration of the chain.
     - parameter iteration: The iteration of the message for which the key is needed.
     - returns: The keys, if it could be generated.
     - throws: `SignalError` errors
     */
    func senderKey(for iteration: UInt32) throws -> SenderMessageKey {
        if chainKey.iteration > iteration {
            // For old (out of order) messages the keys have been saved
            if let messageKey = messageKey(for: iteration) {
                return messageKey
            } else {
                throw SignalError(.duplicateMessage, "Received message with old counter: \(chainKey.iteration), \(iteration)")
            }
        }

        if iteration - chainKey.iteration > SenderKeyState.messageKeyMaximum {
            throw SignalError(.invalidMessage, "Over \(SenderKeyState.messageKeyMaximum) messages into the future")
        }

        // Save all message keys for the messages between the last and the current one
        while chainKey.iteration < iteration {
            // Get message key and advance chain key
            let messageKey = try chainKey.messageKey()

            // Add new message keys without removing old ones (faster)
            add(messageKey: messageKey, removingOldKeys: false)
        }
        // Remove old keys if too many keys
        removeOldMessageKeys()

        // Get message key and advance chain key
        return try chainKey.messageKey()
    }

    // MARK: Protocol Buffers

    /**
     Create a SenderKeyState from a ProtoBuf object.
     - note: This function can be used together with the class variable `object`, to store and retrieve objects from databases.
     - parameter object: The ProtoBuf object containing the data.
     */
    init(from object: Signal_SenderKeyState) throws {
        guard object.hasSenderKeyID, object.hasSenderChainKey,
            object.hasSenderSigningKey, object.senderSigningKey.hasPublic else {
            throw SignalError(.invalidProtoBuf, "Missing data in ProtoBuf object")
        }
        self.keyId = object.senderKeyID
        self.chainKey = try SenderChainKey(from: object.senderChainKey)
        self.signaturePublicKey = try PublicKey(from: object.senderSigningKey.public)
        if object.senderSigningKey.hasPrivate {
            self.signaturePrivateKey = try PrivateKey(from: object.senderSigningKey.private)
        }
        self.messageKeys = try object.senderMessageKeys.map { try SenderMessageKey(from: $0) }
    }

    /// The state converted to a ProtoBuf object
    var protoObject: Signal_SenderKeyState {
        return Signal_SenderKeyState.with {
            $0.senderKeyID = self.keyId
            $0.senderChainKey = self.chainKey.protoObject
            $0.senderSigningKey = Signal_SenderKeyState.SenderSigningKey.with {
                $0.public = self.signaturePublicKey.data
                if let key = self.signaturePrivateKey {
                    $0.private = key.data
                }
            }
            $0.senderMessageKeys = self.messageKeys.map { $0.protoObject }
        }
    }
}

// MARK: Protocol Equatable

extension SenderKeyState: Equatable {

    /**
     Compare tow states for equality
     - Note: Two states are equal if their ids, chain keys, sigature keys and stored message keys match
     - parameter lhs: The first state
     - parameter rhs: The second state
     - returns: `True` if the states are equal
    */
    static func ==(lhs: SenderKeyState, rhs: SenderKeyState) -> Bool {
        return lhs.keyId == rhs.keyId &&
            lhs.chainKey == rhs.chainKey &&
            lhs.signaturePublicKey == rhs.signaturePublicKey &&
            lhs.signaturePrivateKey == rhs.signaturePrivateKey &&
            lhs.messageKeys == rhs.messageKeys
    }


}
