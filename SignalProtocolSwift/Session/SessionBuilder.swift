//
//  SessionBuilder.swift
//  libsignal-protocol-swift
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
struct SessionBuilder {

    var remoteAddress: SignalAddress

    var store: SignalProtocolStoreContext

    /**
     Constructs a session builder.

     - parameter store: the context to store all state information in
     - parameter remoteAddress: the address of the remote user to build a session with
     */
    init(remoteAddress: SignalAddress, store: SignalProtocolStoreContext) {
        self.remoteAddress = remoteAddress
        self.store = store
    }

    /**
     Build a new session from a received pre_key_signal_message.

     After a session is constructed in this way, the embedded signal_message can be decrypted.

     - parameter message: The received `PreKeySignalMessage`.
     - returns: the unsigned pre key ID, if available.
     - throws: `SignalError.untrustedIdentity`, if the identity key of the
     sender is untrusted. `SignalError.invalidKeyID` when there is no local
     pre_key_record that corresponds to the PreKey ID in the message.
     */
    func process(preKeySignalMessage message: PreKeySignalMessage, sessionRecord record: SessionRecord) throws -> UInt32? {

        let theirIdentityKey = message.identityKey

        guard store.isTrusted(identity: theirIdentityKey, for: remoteAddress) else {
            throw SignalError.untrustedIdentity
        }
        let result = try process(preKeySignalMessageV3: message, record: record)
        try store.save(identity: theirIdentityKey, for: remoteAddress)
        return result
    }

    private func process(
        preKeySignalMessageV3 message: PreKeySignalMessage,
        record: SessionRecord) throws -> UInt32? {

        if record.hasSessionState(version: message.version, baseKey: message.baseKey) {
            signalLog(level: .info, "We've already setup a session for this V3 message, letting bundled message fall through...")
            return nil
        }

        let ourSignedPreKey = try store.signedPreKey(for: message.signedPreKeyId)
        let ourIdentityKey = try store.getIdentityKey()
        let ourOneTimePreKey: SessionPreKey?
        if let preKeyID = message.preKeyId {
            ourOneTimePreKey = try store.preKey(for: preKeyID)
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

        record.state.localRegistrationID = try store.getLocalRegistrationID()
        record.state.remoteRegistrationID = message.registrationId
        record.state.aliceBaseKey = message.baseKey

        if message.preKeyId != SessionPreKey.mediumMaxValue {
            return message.preKeyId
        }
        return nil
    }

    /**
     Build a new session from a `SessionPreKeyBundle` retrieved from a server.

     - parameter bundle: A pre key bundle for the destination recipient, retrieved from a server.
     - throws: `SignalError` errors
     */
    func process(preKeyBundle bundle: SessionPreKeyBundle) throws {
        guard store.isTrusted(identity: bundle.identityKey, for: remoteAddress) else {
            signalLog(level: .warning, "Untrusted identity for PreKeyBundle")
            throw SignalError.untrustedIdentity
        }

        guard bundle.identityKey.verify(signature: bundle.signedPreKeySignature,
                                        for: bundle.signedPreKeyPublic.data) else {
            throw SignalError.invalidSignature
        }

        let session = try store.loadSession(for: remoteAddress)
        let ourBaseKey = try KeyPair()
        let preKeyId = bundle.preKeyPublic != nil ? bundle.preKeyId : nil

        let ourIdentityKey = try store.getIdentityKey()
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

        session.state.localRegistrationID = try store.getLocalRegistrationID()
        session.state.remoteRegistrationID = bundle.registrationId
        session.state.aliceBaseKey = ourBaseKey.publicKey

        try store.store(session: session, for: remoteAddress)
        try store.save(identity: bundle.identityKey, for: remoteAddress)
    }
}
