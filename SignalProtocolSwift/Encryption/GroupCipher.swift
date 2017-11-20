//
//  GroupCipher.swift
//  libsignal-protocol-swift
//
//  Created by User on 02.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Use a `GroupCipher` to encrypt and decrypt group messages for already
 existing sessions.
 */
public struct GroupCipher {

    /// The store where the keys are stored
    private let store: SignalProtocolStoreContext

    /// The id of the remote client
    private let senderKeyId: SignalSenderKeyName

    /**
     Create a GroupCipher.
     - parameter store: The store where the keys are stored
     - parameter senderKeyId: The id of the remote client
    */
    init(store: SignalProtocolStoreContext,
         senderKeyId: SignalSenderKeyName) {
        self.store = store
        self.senderKeyId = senderKeyId
    }

    /**
     Encrypt a message for the recipient.
     - parameter plaintext: The data to encrypt
     - returns: The encrypted message
     - throws: `SignalError` errors
    */
    public func encrypt(paddedPlaintext plaintext: [UInt8]) throws -> CipherTextMessage {
        guard let record = try store.loadSenderKey(for: senderKeyId) else {
            throw SignalError(.noSession, "No session")
        }

        guard let state = record.state else {
            throw SignalError(.unknown, "No state in session record")
        }

        guard let signingKeyPrivate = state.signaturePrivateKey else {
            throw SignalError(.invalidKey, "No signature private key")
        }
        let senderKey = try state.chainKey.messageKey()

        let ciphertext = try SignalCrypto.encrypt(
            message: plaintext,
            with: .AES_CBCwithPKCS5,
            key: senderKey.cipherKey,
            iv: senderKey.iv)

        let resultMessage = try SenderKeyMessage(
            keyId: state.keyId,
            iteration: senderKey.iteration,
            cipherText: Data(ciphertext),
            signatureKey: signingKeyPrivate).baseMessage()

        state.chainKey = try state.chainKey.next()
        try store.store(senderKey: record, for: senderKeyId)
        return resultMessage
    }

    public func decrypt(ciphertext: SenderKeyMessage) throws -> [UInt8] {
        guard let record = try store.loadSenderKey(for: senderKeyId) else {
            throw SignalError(.noSession, "No existing session")
        }

        guard let state = record.state(for: ciphertext.keyId) else {
            throw SignalError(.invalidId, "No state for key id")
        }

        guard try ciphertext.verify(signatureKey: state.signaturePublicKey) else {
            throw SignalError(.invalidSignature, "Invalid message signature")
        }
        let senderKey = try getSenderKey(for: state, iteration: ciphertext.iteration)

        let decrypted = try SignalCrypto.decrypt(
            message:  [UInt8](ciphertext.cipherText),
            with: .AES_CBCwithPKCS5,
            key: senderKey.cipherKey,
            iv: senderKey.iv)

        try store.store(senderKey: record, for: senderKeyId)
        return decrypted
    }

    private func getSenderKey(for state: SenderKeyState, iteration: UInt32) throws -> SenderMessageKey {
        if state.chainKey.iteration > iteration {
            // For old (out of order) messages the keys have been saved
            if let messageKey = state.messageKey(for: iteration) {
                return messageKey
            } else {
                throw SignalError(.duplicateMessage, "Received message with old counter: \(state.chainKey.iteration), \(iteration)")
            }
        }

        if iteration - state.chainKey.iteration > SenderKeyState.messageKeyMaximum {
            throw SignalError(.invalidMessage, "Over \(SenderKeyState.messageKeyMaximum) messages into the future")
        }

        // Save all message keys for the messages between the last and the current one
        while state.chainKey.iteration < iteration {
            let messageKey = try state.chainKey.messageKey()

            // Add new message keys without removing old ones (faster)
            state.add(messageKey: messageKey, removingOldKeys: false)
            let nextChainKey = try state.chainKey.next()
            state.chainKey = nextChainKey
        }
        // Remove old keys if too many keys
        state.removeOldMessageKeys()

        let key = try state.chainKey.messageKey()
        state.chainKey = try state.chainKey.next()
        return key
    }
}


