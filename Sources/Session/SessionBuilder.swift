//
//  SessionBuilder.swift
//  SignalProtocolSwift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


/**
 * Session builder is responsible for setting up encrypted sessions.
 * Once a session has been established, session_cipher
 * can be used to encrypt/decrypt messages in that session.
 *
 * Sessions are built from one these different possible vectors:
 * - A session_pre_key_bundle retrieved from a server
 * - A pre_key_signal_message received from a client
 *
 * Sessions are constructed per Signal Protocol address
 * (recipient name + device ID tuple). Remote logical users are identified by
 * their recipient name, and each logical recipient can have multiple
 * physical devices.
 */
struct SessionBuilder<Context: KeyStore> {

    /// The store to save and retrieve keys from
    var store: Context

    /// The address of the other party
    var remoteAddress: Context.Address

    /**
     Constructs a session builder.
     - parameter store: the context to store all state information in
     - parameter remoteAddress: the address of the remote user to build a session with
     */
    init(remoteAddress: Context.Address, store: Context) {
        self.remoteAddress = remoteAddress
        self.store = store
    }

    /**
     Build a new session from a received PreKeySignalMessage.

     After a session is constructed in this way, the embedded SignalMessage can be decrypted.

     - parameter message: The received `PreKeySignalMessage`.
     - returns: the unsigned pre key Id, if available.
     - throws: `SignalError.untrustedIdentity`, if the identity key of the
     sender is untrusted. `SignalError.invalidKeyID` when there is no local
     PreKeyRecord that corresponds to the PreKey ID in the message.
     */
    func process(preKeySignalMessage message: PreKeySignalMessage, sessionRecord record: SessionRecord) throws -> UInt32? {

        let theirIdentityKey = message.identityKey

        guard try store.identityKeyStore.isTrusted(identity: theirIdentityKey, for: remoteAddress) else {
            throw SignalError(.untrustedIdentity, "Untrusted identity for \(remoteAddress)")
        }
        let result = try process(preKeySignalMessageV3: message, record: record)
        try store.identityKeyStore.store(identity: theirIdentityKey, for: remoteAddress)
        return result
    }

    /**
     Build a new session from a received PreKeySignalMessage.
     - parameter message: The received `PreKeySignalMessage`.
     - returns: the unsigned pre key Id, if available.
     - throws: `SignalError` errors
     */
    private func process(
        preKeySignalMessageV3 message: PreKeySignalMessage,
        record: SessionRecord) throws -> UInt32? {

        if record.hasSessionState(baseKey: message.baseKey) {
            // We've already setup a session for this V3 message, letting bundled message fall through...
            return nil
        }

        let ourSignedPreKey: SessionSignedPreKey = try store.signedPreKeyStore.signedPreKey(for: message.signedPreKeyId)
        let ourIdentityKey = try store.identityKeyStore.getIdentityKey()
        let ourOneTimePreKey: SessionPreKey?
        if let preKeyID = message.preKeyId {
            ourOneTimePreKey = try store.preKeyStore.preKey(for: preKeyID)
        } else {
            ourOneTimePreKey = nil
        }

        if !record.isFresh {
            record.archiveCurrentState()
        }

        try record.state.bobInitialize(
            ourIdentityKey: ourIdentityKey,
            ourSignedPreKey: ourSignedPreKey.keyPair,
            ourOneTimePreKey: ourOneTimePreKey?.keyPair,
            ourRatchetKey: ourSignedPreKey.keyPair,
            theirIdentityKey: message.identityKey,
            theirBaseKey: message.baseKey)

        record.state.aliceBaseKey = message.baseKey

        if message.preKeyId != SessionPreKey.mediumMaxValue {
            return message.preKeyId
        }
        return nil
    }

    /**
     Build a new session from a `SessionPreKeyBundle` retrieved from a server.
     
     - note: Possible errors:
     - `untrustedIdentity`, the identity key of the bundle is untrusted
     - `invalidSignature` if the signed pre key signature is invalid
     - `storageError` if the key stores could not be accessed
     - `invalidProtobuf` if data is corrupt
     - parameter bundle: A pre key bundle for the destination recipient, retrieved from a server.
     - throws: `SignalError` errors
     */
    func process(preKeyBundle bundle: SessionPreKeyBundle) throws {
        guard try store.identityKeyStore.isTrusted(identity: bundle.identityKey, for: remoteAddress) else {
            throw SignalError(.untrustedIdentity, "Untrusted identity for PreKeyBundle")
        }

        guard bundle.identityKey.verify(signature: bundle.signedPreKeySignature,
                                        for: bundle.signedPreKeyPublic.data) else {
            throw SignalError(.invalidSignature, "Invalid signed pre key signature")
        }

        let session: SessionRecord = try store.sessionStore.loadSession(for: remoteAddress)
        let ourBaseKey = try KeyPair()
        let preKeyId = bundle.preKeyPublic != nil ? bundle.preKeyId : nil

        let ourIdentityKey = try store.identityKeyStore.getIdentityKey()
        if !session.isFresh {
            session.archiveCurrentState()
        }

        try session.state.aliceInitialize(
            ourIdentityKey: ourIdentityKey,
            ourBaseKey: ourBaseKey,
            theirIdentityKey: bundle.identityKey,
            theirSignedPreKey: bundle.signedPreKeyPublic,
            theirOneTimePreKey: bundle.preKeyPublic,
            theirRatchetKey: bundle.signedPreKeyPublic)

        session.state.pendingPreKey = PendingPreKey(
            preKeyId: preKeyId,
            signedPreKeyId: bundle.signedPreKeyId,
            baseKey: ourBaseKey.publicKey)

        session.state.aliceBaseKey = ourBaseKey.publicKey

        try store.sessionStore.store(session: session, for: remoteAddress)
        try store.identityKeyStore.store(identity: bundle.identityKey, for: remoteAddress)
    }
}
