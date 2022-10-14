//
//  GroupCipher.swift
//  SignalProtocolSwift
//
//  Created by User on 02.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Use a `GroupCipher` to encrypt and decrypt group messages for already
 existing sessions.
 */
public struct GroupCipher<Context: GroupKeyStore> {

    /// The store where the keys are stored
    private let store: Context

    /// The id of the remote client
    private let address: Context.GroupAddress

    /**
     Create a GroupCipher.
     - parameter store: The store where the keys are stored
     - parameter senderKeyId: The id of the remote client
    */
    init(address: Context.GroupAddress, store: Context) {
        self.store = store
        self.address = address
    }

    /**
     Create a GroupCipher.
     - note: Possible errors are:
     - `invalidType`, if the message is not a distribution message
     - `invalidProtoBuf`, if data is missing or corrupt, or an invalid sender key was stored
     - `storageError`, if the sender key could not be saved in the store
     - parameter message: The distribution message
     - throws: `SignalError` errors.
     */
    public func process(message: CipherTextMessage) throws {
        guard message.type == .senderKeyDistribution else {
            throw SignalError(.invalidType, "Invalid message type \(message.type)")
        }
        let object = try SenderKeyDistributionMessage(from: message.data)
        try process(distributionMessage: object)
    }

    /**
     Create a new group session from a distribution message.
     - note: Possible errors are:
     - `invalidProtoBuf`, if an invalid sender key was stored
     - `storageError`, if the sender key could not be saved in the store
     - parameter message: The distribution message
     - throws: `SignalError` errors.
     */
    public func process(distributionMessage: SenderKeyDistributionMessage) throws {
        let senderKey = try store.senderKeyStore.senderKey(for: address) ?? SenderKeyRecord()

        senderKey.addState(
            id: distributionMessage.id,
            iteration: distributionMessage.iteration,
            chainKey: distributionMessage.chainKey,
            signaturePublicKey: distributionMessage.signatureKey,
            signaturePrivateKey: nil)

        try store.senderKeyStore.store(senderKey: senderKey, for: address)
    }

    /**
     Create a new session and generate a distribution message.
     - note: Possible errors are:
     - `invalidProtoBuf`, if an invalid sender key was stored
     - `storageError`, if the sender key could not be saved in the store
     - `noRandomBytes`, if the crypto provider failed to provide random data
     - `curveError`, if no sender signing key could be created
     - `unknown`, if no state exists in the sender key record
     - returns: The distribution message.
     - throws: `SignalError` errors
     */
    public func createSession() throws -> SenderKeyDistributionMessage {

        let record = try store.senderKeyStore.senderKey(for: address) ?? SenderKeyRecord()

        if record.isEmpty {
            let senderKeyId = try SignalCrypto.generateSenderKeyId()
            let senderKey = try SignalCrypto.generateSenderKey()
            let senderSigningKey = try SignalCrypto.generateSenderSigningKey()
            record.setSenderKey(id: senderKeyId,
                                iteration: 0,
                                chainKey: senderKey,
                                signatureKeyPair: senderSigningKey)
            try store.senderKeyStore.store(senderKey: record, for: address)
        }

        guard let state = record.state else {
            throw SignalError(.unknown, "No state in record")
        }

        let chainKey = state.chainKey
        let seed = chainKey.chainKey

        return SenderKeyDistributionMessage(
            id: state.keyId,
            iteration: chainKey.iteration,
            chainKey: seed,
            signatureKey: state.signaturePublicKey)
    }

    /**
     Encrypt a message for the recipient.
     - parameter plaintext: The data to encrypt
     - returns: The encrypted message
     - throws: `SignalError` errors
    */
    public func encrypt(_ plaintext: Data) throws -> CipherTextMessage {
        let record = try loadRecord()

        guard let state = record.state else {
            throw SignalError(.unknown, "No state in session record")
        }

        guard let signingKeyPrivate = state.signaturePrivateKey else {
            throw SignalError(.invalidKey, "No signature private key")
        }
        // Get message key and advance chain key
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

        try store.senderKeyStore.store(senderKey: record, for: address)
        return resultMessage
    }

    /**
     Decrypt a message from the group member.
     - note: The following errors can be thrown:
     - `noSession`: No session set up for this member.
     - `invalidId`: No session state available for the message.
     - `invalidSignature`: The signature doesn't match the message.
     - `decryptionError`: The message could not be decrypted.
     - `storageError`: The new session record could not be stored.
     - `invalidProtoBuf`: The session record could not be serialized for storage.
     - parameter ciphertext: The message to decrypt
     - returns: The decrypted message
     - throws: `SignalError` errors
     */
    public func decrypt(ciphertext: SenderKeyMessage) throws -> Data {
        let record = try loadRecord()

        guard let state = record.state(for: ciphertext.keyId) else {
            throw SignalError(.invalidId, "No state for key id")
        }

        guard try ciphertext.verify(signatureKey: state.signaturePublicKey) else {
            throw SignalError(.invalidSignature, "Invalid message signature")
        }
        let senderKey = try state.senderKey(for: ciphertext.iteration) 

        let decrypted = try SignalCrypto.decrypt(
            message: ciphertext.cipherText,
            with: .AES_CBCwithPKCS5,
            key: senderKey.cipherKey,
            iv: senderKey.iv)

        try store.senderKeyStore.store(senderKey: record, for: address)
        return decrypted
    }

    /**
     Load the record for the remote address.
     - throws: `SignalError` of type `noSession`
     - returns: The record for the remote address
     */
    private func loadRecord() throws -> SenderKeyRecord {
        guard let record: SenderKeyRecord = try store.senderKeyStore.senderKey(for: address) else {
            throw SignalError(.noSession, "No existing session")
        }
        return record
    }
}


