//
//  SessionCipher.swift
//  SignalProtocolSwift
//
//  Created by User on 02.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The main entry point for Signal Protocol encrypt/decrypt operations.

 This class can be used to establish a session by processing a pre key bundle
 and for all subsequent encrypt/decrypt operations within that session.
 */
public struct SessionCipher<Context: KeyStore> {

    // MARK: Variables

    /// The local data store to use for state information
    private var store: Context

    /// The address of the remote party
    private var remoteAddress: Context.Address

    // MARK: Initialization

    /**
     Construct a session cipher for encrypt/decrypt operations on a session.
     In order to use a SessionCipher, a session must be created by processing a
     pre key bundle or a PreKeySignalMessage.

     The store and global contexts must remain valid for the lifetime of the
     session cipher.

     When finished, free the returned instance by calling session_cipher_free().

     - parameter store: The KeyStore to store all state information in
     - parameter remoteAddress: The remote address that messages will be encrypted to or decrypted from.
     - returns: A freshly allocated session cipher instance
     */
    public init(store: Context, remoteAddress: Context.Address) {
        self.store = store
        self.remoteAddress = remoteAddress
    }

    // MARK: Public functions

    /**
     Encrypt a message.
     - parameter message: The plaintext message bytes, optionally padded to a constant multiple.
     - returns: The ciphertext message encrypted to the recipient+device tuple
     - throws: Errors of Type `SignalError`
     */
    public func encrypt(_ message: Data) throws -> CipherTextMessage {
        let record = try loadSession()
        guard let senderChain = record.state.senderChain else {
            throw SignalError(.unknown, "No sender chain for session state")
        }
        let chainKey = senderChain.chainKey
        let messageKeys = try chainKey.messageKeys()
        let senderEphemeral = senderChain.ratchetKey.publicKey
        let ciphertext = try getCiphertext(messageKeys: messageKeys, plaintext: message)

        guard let localIdentityKey = record.state.localIdentity,
            let remoteIdentityKey = record.state.remoteIdentity else {
            throw SignalError(.unknown, "No local or remote identity in state")
        }

        let resultMessage = try SignalMessage(
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
        try store.sessionStore.store(session: record, for: remoteAddress)
        if preKeyMessage != nil {
            return try preKeyMessage!.baseMessage()
        }
        return try resultMessage.baseMessage()
    }

    /**
     Decrypt a message.
     
     - note: Possible errors:
     - `invalidMessage` if the input is not valid ciphertext.
     - `duplicateMessage` if the input is a message that has already been received.
     - `invalidKeyID` when there is no local pre_key_record that corresponds to the pre key ID in the message.
     - `invalidKey` when the message is formatted incorrectly.
     - `untrustedIdentity` when the identity key of the sender is untrusted.
     - `noSession` if there is no established session for this contact.
     - `invalidType` if the type of the message is not supported
    */
    public func decrypt(_ message: CipherTextMessage) throws -> Data {
        switch message.type {
        case .preKey:
            let mess = try PreKeySignalMessage(from: message.data)
            return try decrypt(preKeySignalMessage: mess)
        case .signal:
            let mess = try SignalMessage(from: message.data)
            return try decrypt(signalMessage: mess)
        default:
            throw SignalError(.invalidType, "Not a PreKeySignalMessage or SignalMessage")
        }
    }

    /**
     Decrypt a message.

     - note: Possible errors:
     - `invalidMessage` if the input is not valid ciphertext.
     - `duplicateMessage` if the input is a message that has already been received.
     - `invalidKeyID` when there is no local pre_key_record that corresponds to the pre key ID in the message.
     - `invalidKey` when the message is formatted incorrectly.
     - `untrustedIdentity` when the identity key of the sender is untrusted.
     - parameter ciphertext: The PreKeySignalMessage to decrypt.
     - returns: The decrypted plaintext
     - throws: `SignalError` errors
     */
    public func decrypt(preKeySignalMessage ciphertext: PreKeySignalMessage) throws -> Data {
        let record = try loadSession()

        let builder = SessionBuilder(remoteAddress: remoteAddress, store: store)
        let unsignedPreKeyId =
            try builder.process(preKeySignalMessage: ciphertext, sessionRecord: record)
        let plaintext = try decrypt(from: record, and: ciphertext.message)
        try store.sessionStore.store(session: record, for: remoteAddress)
        if let id = unsignedPreKeyId, store.preKeyStore.containsPreKey(for: id) {
            try store.preKeyStore.removePreKey(for: id)
        }
        return plaintext
    }

    /**
    Decrypt a message.

     - note: Possible errors:
     - `invalidMessage` if the input is not valid ciphertext.
     - `duplicateMessage` if the input is a message that has already been received.
     - `noSession` if there is no established session for this contact.

     - parameter ciphertext: The SignalMessage to decrypt.
     - returns: The decrypted plaintext.
     - throws: `SignalError` errors
     */
    public func decrypt(signalMessage ciphertext: SignalMessage) throws -> Data {
        let record = try loadSession()
        let plaintext = try decrypt(from: record, and: ciphertext)

        try store.sessionStore.store(session: record, for: remoteAddress)
        return plaintext
    }

    /**
     Build a new session from a `SessionPreKeyBundle` retrieved from a server.

     - parameter bundle: A pre key bundle for the destination recipient, retrieved from a server.
     - throws: `SignalError` errors
     */
    public func process(preKeyBundle bundle: SessionPreKeyBundle) throws {
        let builder = SessionBuilder(remoteAddress: remoteAddress, store: store)
        try builder.process(preKeyBundle: bundle)
    }

    // MARK: Private functions

    /**
     Load the session record for the remote address
     - throws: `SignalError`of type `storageError`
     - returns: The session record
    */
    private func loadSession() throws -> SessionRecord {
        return try store.sessionStore.loadSession(for: remoteAddress)
    }

    /**
     Try to decrypt a SignalMessage with one of the stored sessions in the `SessionRecord`. If a session can decrypt the message it will be promoted to the active session.
     - parameter record: The `SessionRecord` containing the sessions
     - parameter signalMessage: The message to decrypt
     - returns: The decrypted plaintext
     - throws: Errors of type `SignalError`
    */
    private func decrypt(from record: SessionRecord, and signalMessage: SignalMessage) throws -> Data {

        do {
            return try decrypt(from: record.state, and: signalMessage)
        } catch let error as SignalError where error.type == .invalidMessage {
            // Invalid message means that the current state is not the right one
        }

        for index in 0..<record.previousStates.count {
            let state = record.previousStates[index]
            do {
                let plaintext = try decrypt(from: state, and: signalMessage)
                record.promoteState(state: state)
                return plaintext
            } catch let error as SignalError where error.type == .invalidMessage {
                // Invalid message means that the current state is not the right one
            }
        }
        throw SignalError(.invalidMessage, "No valid sessions")
    }

    /**
     Try to decrypt a `SignalMessage` with a specific `SessionState`.

     - parameter state: The `SessionState` to try
     - parameter signalMessage: The message to decrypt
     - returns: The decrypted plaintext
     - throws: Errors of type `SignalError`, `SignalError.invalidMessage` if the decryption failed.
    */
    private func decrypt(from state: SessionState, and signalMessage: SignalMessage) throws -> Data {

        guard state.senderChain != nil else {
            throw SignalError(.invalidMessage, "Uninitialized session!")
        }

        let chainKey = try getOrCreateChainKey(state: state, theirEphemeral: signalMessage.senderRatchetKey)

        let messageKeys = try getOrCreateMessageKeys(
            state: state,
            theirEphemeral: signalMessage.senderRatchetKey,
            chainKey: chainKey,
            counter: signalMessage.counter)

        guard let remoteIdentity = state.remoteIdentity else {
            throw SignalError(.unknown, "No remote identity in state")
        }
        guard let localIdentity = state.localIdentity else {
            throw SignalError(.unknown, "No local identity in state")
        }
        guard try signalMessage.verifyMac(
            senderIdentityKey: remoteIdentity,
            receiverIdentityKey: localIdentity,
            macKey: messageKeys.macKey) else {
                throw SignalError(.invalidMessage, "Message mac not verified")
        }

        let plaintext = try getPlaintext(messageKeys: messageKeys, ciphertext: signalMessage.cipherText)

        state.pendingPreKey = nil
        return plaintext
    }

    /**
     Retrieve previously stored message keys or create them from the chain.
     - parameter state: The state in which decryption happens
     - parameter theirEphemeral: The public key of the receiver chain to use
     - parameter chainKey: The current chain key
     - parameter counter: The counter of the message in the chain
     - returns: The keys for the message
     - throws: `SignalError` errors
     */
    private func getOrCreateMessageKeys(
        state: SessionState,
        theirEphemeral: PublicKey,
        chainKey: RatchetChainKey,
        counter: UInt32) throws -> RatchetMessageKeys {

        if chainKey.index > counter {
            guard let messageKeysResult = state.removeMessageKeys(for: theirEphemeral, and: counter) else {
                throw SignalError(.duplicateMessage, "Received message with old counter: \(chainKey.index), \(counter)")
            }
            return messageKeysResult
        }

        if counter - chainKey.index > SenderKeyState.messageKeyMaximum {
            throw SignalError(.invalidMessage, "Over \(SenderKeyState.messageKeyMaximum) messages into the future!")
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

    /**
     Retrieve the chain key for a state and receiver chain key.
     - parameter state: The state in which decryption happens
     - parameter theirEphemeral: The public key of the receiver chain to use
     - returns: The keys for the chain
     - throws: `SignalError` errors
     */
    private func getOrCreateChainKey(state: SessionState, theirEphemeral: PublicKey) throws -> RatchetChainKey {

        if let resultKey = state.receiverChain(for: theirEphemeral)?.chainKey {
            return resultKey
        }

        guard let rootKey = state.rootKey else {
            throw SignalError(.unknown, "No root key in state")
        }

        guard let senderChain = state.senderChain else {
            throw SignalError(.unknown, "No sender chain in state")
        }

        let ourEphemeral = senderChain.ratchetKey

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

        let previousChainKey = senderChain.chainKey

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

    /**
     Encrypt a message.
     - parameter messageKeys: The keys used for encryption
     - parameter plaintext: The data to encrypt
     - returns: The encrypted ciphertext
     - throws: `SignalError` of type `encryptionError`
    */
    private func getCiphertext(messageKeys: RatchetMessageKeys, plaintext: Data) throws -> Data {
        return try SignalCrypto.encrypt(
            message: plaintext,
            with: .AES_CTRnoPadding,
            key: messageKeys.cipherKey,
            iv: messageKeys.iv)
    }

    /**
     Decrypt a message.
     - parameter messageKeys: The keys used for encryption
     - parameter plaintext: The data to encrypt
     - returns: The encrypted ciphertext
     - throws: `SignalError` of type `encryptionError`
     */
    private func getPlaintext(messageKeys: RatchetMessageKeys, ciphertext: Data) throws -> Data {
        return try SignalCrypto.decrypt(
            message: ciphertext,
            with: .AES_CTRnoPadding,
            key: messageKeys.cipherKey,
            iv: messageKeys.iv)
    }
}
