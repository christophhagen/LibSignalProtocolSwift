//
//  SessionCipher.swift
//  libsignal-protocol-swift
//
//  Created by User on 02.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The main entry point for Signal Protocol encrypt/decrypt operations.

 Once a session has been established with session_builder,
 this class can be used for all encrypt/decrypt operations
 within that session.
 */
struct SessionCipher {

    // MARK: Variables

    var store: SignalProtocolStoreContext

    var remoteAddress: SignalAddress

    var builder: SessionBuilder

    // MARK: Initialization

    /**
     Construct a session cipher for encrypt/decrypt operations on a session.
     In order to use session_cipher, a session must have already been created
     and stored using session_builder.

     The store and global contexts must remain valid for the lifetime of the
     session cipher.

     When finished, free the returned instance by calling session_cipher_free().

     - parameter store: The SignalProtocolStoreContext to store all state information in
     - parameter remoteAddress: The remote address that messages will be encrypted to or decrypted from.
     - returns: A freshly allocated session cipher instance
     */
    init(store: SignalProtocolStoreContext, remoteAddress: SignalAddress) {
        self.store = store
        self.remoteAddress = remoteAddress
        self.builder = SessionBuilder(remoteAddress: remoteAddress, store: store)
    }

    // MARK: Public functions

    /**
     Encrypt a message.
     - parameter message: The plaintext message bytes, optionally padded to a constant multiple.
     - returns: The ciphertext message encrypted to the recipient+device tuple
     - throws: Errors of Type `SignalError`
     */
    func encrypt(paddedMessage message: [UInt8]) throws -> CipherTextMessage {
        let record = try loadSession()
        guard let chainKey = record.state.senderChain?.chainKey else {
            throw SignalError.unknown
        }

        let messageKeys = try chainKey.messageKeys()

        guard let senderEphemeral = record.state.senderChain?.ratchetKey.publicKey else {
            throw SignalError.unknown
        }
        let sessionVersion = record.state.version

        let ciphertext = try getCiphertext(
            version: sessionVersion,
            messageKeys: messageKeys,
            plaintext: message)

        guard let localIdentityKey = record.state.localIdentity,
            let remoteIdentityKey = record.state.remoteIdentity else {
            throw SignalError.unknown
        }

        let resultMessage = try SignalMessage(
            messageVersion: sessionVersion,
            macKey: messageKeys.macKey,
            senderRatchetKey: senderEphemeral,
            counter: chainKey.index,
            previousCounter: record.state.previousCounter,
            cipherText: ciphertext,
            senderIdentityKey: localIdentityKey,
            receiverIdentityKey: remoteIdentityKey)

        let preKeyMessage: PreKeySignalMessage?
        if let pendingPreKey = record.state.pendingPreKey {
            preKeyMessage = PreKeySignalMessage(
                messageVersion: sessionVersion,
                registrationId: record.state.localRegistrationID,
                preKeyId: pendingPreKey.preKeyId,
                signedPreKeyId: pendingPreKey.signedPreKeyId,
                baseKey: pendingPreKey.baseKey,
                identityKey: localIdentityKey,
                message: resultMessage)
        } else {
            preKeyMessage = nil
        }

        let nextChainKey = try chainKey.next()
        record.state.senderChain?.chainKey = nextChainKey
        try store.store(session: record, for: remoteAddress)
        if preKeyMessage != nil {
            return try preKeyMessage!.baseMessage()
        }
        return try resultMessage.baseMessage()
    }

    /**
     Decrypt a message.

     - parameter ciphertext: The PreKeySignalMessage to decrypt.
     - returns: The decrypted plaintext
     - throws: `SignalError.invalidMessage` if the input is not valid ciphertext.
     `SignalError.duplicateMessage` if the input is a message that has already been received.
     `SignalError.legacyMessage` if the input is a message formatted by a protocol
     version that is no longer supported. `SignalError.invalidKeyID` when there is no
     local pre_key_record that corresponds to the pre key ID in the message.
     `SignalError.invalidKey` when the message is formatted incorrectly.
     `SignalError.untrustedIdentity` when the identity key of the sender is untrusted.
     */
    func decrypt(preKeySignalMessage ciphertext: PreKeySignalMessage) throws -> [UInt8] {
        let record = try loadSession()
        let unsignedPreKeyId =
            try builder.process(preKeySignalMessage: ciphertext, sessionRecord: record)
        let plaintext = try decrypt(from: record, and: ciphertext.message)
        try store.store(session: record, for: remoteAddress)
        if let id = unsignedPreKeyId, store.containsPreKey(for: id) {
            try store.removePreKey(for: id)
        }
        return plaintext
    }

    /**
    Decrypt a message.

     - parameter ciphertext: The SignalMessage to decrypt.
     - returns: The decrypted plaintext.
     - throws: `SignalError.invalidMessage` if the input is not valid ciphertext. `SignalError.duplicateMessage` if the input is a message that has already been received. `SignalError.legacyMessage` if the input is a message formatted by a protocol version that is no longer supported. `SignalError.noSession` if there is no established session for this contact.
     */
    func decrypt(signalMessage ciphertext: SignalMessage) throws -> [UInt8] {
        let record = try loadSession()
        let plaintext = try decrypt(from: record, and: ciphertext)

        try store.store(session: record, for: remoteAddress)
        return plaintext
    }

    /**
     Gets the remote registration ID for this session cipher.
     */
    func getRemoteRegistrationId() throws -> UInt32 {
        return try loadSession().state.remoteRegistrationID
    }

    /**
     Gets the version of the session associated with this session cipher.
     */
    func getSessionVersion() throws -> UInt8 {
        return try loadSession().state.version
    }

    // MARK: Private functions

    /**
     Load the session record for the remote address
    */
    private func loadSession() throws -> SessionRecord {
        return try store.loadSession(for: remoteAddress)
    }

    /**
     Try to decrypt a SignalMessage with one of the stored sessions in the `SessionRecord`. If a session can decrypt the message it will be promoted to the active session.
     - parameter record: The `SessionRecord` containing the sessions
     - parameter signalMessage: The message to decrypt
     - returns: The decrypted plaintext
     - throws: Errors of type `SignalError`
    */
    private func decrypt(from record: SessionRecord, and signalMessage: SignalMessage) throws -> [UInt8] {

        do {
            let plaintext = try decrypt(from: record.state, and: signalMessage)
            return plaintext
        } catch SignalError.invalidMessage {

        }

        for index in 0..<record.previousStates.count {
            let state = record.previousStates[index]
            do {
                let plaintext = try decrypt(from: state, and: signalMessage)
                record.previousStates.remove(at: index)
                record.promoteState(state: state)
                return plaintext
            } catch SignalError.invalidMessage {

            }
        }

        signalLog(level: .warning, "No valid sessions")
        throw SignalError.invalidMessage
    }

    /**
     Try to decrypt a `SignalMessage` with a specific `SessionState`.

     - parameter state: The `SessionState` to try
     - parameter signalMessage: The message to decrypt
     - returns: The decrypted plaintext
     - throws: Errors of type `SignalError`, `SignalError.invalidMessage` if the decryption failed.
    */
    private func decrypt(from state: SessionState, and signalMessage: SignalMessage) throws -> [UInt8] {

        guard state.senderChain != nil else {
            signalLog(level: .warning, "Uninitialized session!")
            throw SignalError.invalidMessage
        }

        guard signalMessage.messageVersion == state.version else {
            signalLog(level: .warning, "Message version \(signalMessage.messageVersion), but session version \(state.version)")
            throw SignalError.invalidMessage
        }

        let chainKey = try getOrCreateChainKey(state: state, theirEphemeral: signalMessage.senderRatchetKey)

        let messageKeys = try getOrCreateMessageKeys(
            state: state,
            theirEphemeral: signalMessage.senderRatchetKey,
            chainKey: chainKey,
            counter: signalMessage.counter)

        guard let remoteIdentity = state.remoteIdentity else {
            throw SignalError.unknown
        }
        guard let localIdentity = state.localIdentity else {
            throw SignalError.unknown
        }
        guard signalMessage.verifyMac(
            senderIdentityKey: remoteIdentity,
            receiverIdentityKey: localIdentity,
            macKey: messageKeys.macKey) else {
                signalLog(level: .warning, "Message mac not verified")
                throw SignalError.invalidMessage
        }

        let plaintext = try getPlaintext(
            messageVersion: signalMessage.messageVersion,
            messageKeys: messageKeys,
            ciphertext: signalMessage.cipherText)

        state.pendingPreKey = nil
        return plaintext
    }

    private func getOrCreateMessageKeys(
        state: SessionState,
        theirEphemeral: PublicKey,
        chainKey: RatchetChainKey,
        counter: UInt32) throws -> RatchetMessageKeys {

        if chainKey.index > counter {
            guard let messageKeysResult = state.removeMessageKeys(for: theirEphemeral, and: counter) else {
                signalLog(level: .warning, "Received message with old counter: \(chainKey.index), \(counter)")
                throw SignalError.duplicateMessage
            }
            return messageKeysResult
        }

        if counter - chainKey.index > SenderKeyState.messageKeyMaximum {
            signalLog(level: .warning, "Over \(SenderKeyState.messageKeyMaximum) messages into the future!")
            throw SignalError.invalidMessage
        }

        var currentChainKey = chainKey
        while currentChainKey.index < counter {
            let messageKeysResult = try currentChainKey.messageKeys()

            state.set(messageKeys: messageKeysResult, for: theirEphemeral)
            currentChainKey = try currentChainKey.next()
        }
        let nextChainKey = try currentChainKey.next()
        try state.set(receiverChainKey: nextChainKey, for: theirEphemeral)
        return try currentChainKey.messageKeys()
    }

    private func getOrCreateChainKey(state: SessionState, theirEphemeral: PublicKey) throws -> RatchetChainKey {

        if let resultKey = state.receiverChain(for: theirEphemeral)?.chainKey {
            return resultKey
        }

        guard let rootKey = state.rootKey else {
            throw SignalError.unknown
        }

        guard let ourEphemeral = state.senderChain?.ratchetKey else {
            throw SignalError.unknown
        }

        let (receiverRootKey, receiverChainKey) = try rootKey.createChain(
            theirRatchetKey: theirEphemeral,
            ourRatchetKey: ourEphemeral.privateKey)

        let ourNewEphemeral = try KeyPair()

        let (senderRootKey, senderChainKey) = try receiverRootKey.createChain(
            theirRatchetKey: theirEphemeral,
            ourRatchetKey: ourNewEphemeral.privateKey)

        state.rootKey = senderRootKey
        let receiverChain = ReceiverChain(ratchetKey: theirEphemeral, chainKey: receiverChainKey)
        state.add(receiverChain: receiverChain)

        guard let previousChainKey = state.senderChain?.chainKey else {
            throw SignalError.unknown
        }

        if previousChainKey.index > 0 {
            state.previousCounter = previousChainKey.index - 1
        } else {
            state.previousCounter = 0
        }
        state.senderChain = SenderChain(
            ratchetKey: ourNewEphemeral,
            chainKey: senderChainKey)

        return receiverChainKey

    }

    private func getCiphertext(version: UInt8, messageKeys: RatchetMessageKeys, plaintext: [UInt8]) throws -> [UInt8] {

        if version >= 3 {
            return try SignalCrypto.encrypt(
                message: plaintext,
                with: .AES_CBCwithPKCS5,
                key: messageKeys.cipherKey,
                iv: messageKeys.iv)
        } else {
            var iv = [UInt8](repeating: 0, count: 16)
            let counter = messageKeys.counter
            iv[3] = UInt8(counter & 0x00FF)
            iv[2] = UInt8((counter >> 8) & 0x00FF)
            iv[1] = UInt8((counter >> 16) & 0x00FF)
            iv[0] = UInt8((counter >> 24) & 0x00FF)

            return try SignalCrypto.encrypt(
                message: plaintext,
                with: .AES_CTRnoPadding,
                key: messageKeys.cipherKey,
                iv: iv)
        }
    }

    private func getPlaintext(messageVersion: UInt8, messageKeys: RatchetMessageKeys, ciphertext: [UInt8]) throws -> [UInt8] {

        if messageVersion >= 3 {
            return try SignalCrypto.decrypt(
                message: ciphertext,
                with: .AES_CBCwithPKCS5,
                key: messageKeys.cipherKey,
                iv: messageKeys.iv)
        } else {
            var iv = [UInt8](repeating: 0, count: 16)
            let counter = messageKeys.counter
            iv[3] = UInt8(counter & 0x00FF)
            iv[2] = UInt8((counter >> 8) & 0x00FF)
            iv[1] = UInt8((counter >> 16) & 0x00FF)
            iv[0] = UInt8((counter >> 24) & 0x00FF)

            return try SignalCrypto.decrypt(
                message: ciphertext,
                with: .AES_CTRnoPadding,
                key: messageKeys.cipherKey,
                iv: iv)
        }
    }
}
