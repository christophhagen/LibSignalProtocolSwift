//
//  GroupCipher.swift
//  libsignal-protocol-swift
//
//  Created by User on 02.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct GroupCipher {

    var store: SignalProtocolStoreContext

    var senderKeyId: SignalSenderKeyName

    init(store: SignalProtocolStoreContext,
         senderKeyId: SignalSenderKeyName) {
        self.store = store
        self.senderKeyId = senderKeyId
    }

    func encrypt(paddedPlaintext plaintext: [UInt8]) throws -> CipherTextMessage {

        guard let record = try store.loadSenderKey(for: senderKeyId) else {
            throw SignalError.noSession
        }

        guard let state = record.state else {
            throw SignalError.unknown
        }

        guard let signingKeyPrivate = state.signaturePrivateKey else {
            throw SignalError.invalidKey
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

    func decrypt(ciphertext: SenderKeyMessage) throws -> [UInt8] {
        guard let record = try store.loadSenderKey(for: senderKeyId) else {
            throw SignalError.noSession
        }

        guard let state = record.state(for: ciphertext.keyId) else {
            throw SignalError.invalidKeyID
        }

        guard ciphertext.verify(signatureKey: state.signaturePublicKey) else {
            throw SignalError.invalidSignature
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

    func getSenderKey(for state: SenderKeyState, iteration: UInt32) throws -> SenderMessageKey {
        // TODO: Remove
        if state.chainKey.iteration > iteration {
            // For old (out of order) messages the keys have been saved
            if let messageKey = state.messageKey(for: iteration) {
                return messageKey
            } else {
                signalLog(level: .warning, "Received message with old counter: \(state.chainKey.iteration), \(iteration)")
                throw SignalError.duplicateMessage
            }
        }

        if iteration - state.chainKey.iteration > SenderKeyState.messageKeyMaximum {
            signalLog(level: .warning, "Over \(SenderKeyState.messageKeyMaximum) messages into the future")
            throw SignalError.invalidMessage
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


