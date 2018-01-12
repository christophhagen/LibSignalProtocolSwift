//
//  SignalServerConnection.swift
//  SignalCommunication-iOSTests
//
//  Created by User on 16.11.17.
//

import Foundation

private let preKeyMaxCount = 10

public final class SignalServerConnection<Context: SignalProtocolStoreContext, Server: SignalServer> where Server.ServerAddress == SignalAddress {

    private let store: Context

    private let server: Server

    init(store: Context, server: Server) {
        self.store = store
        self.server = server
    }

    /**
     Store the identity of the local client on the server.
     */
    public func uploadIdentity() throws {
        let key = try store.identityKeyStore.getIdentityKey().publicKey
        let registrationId = try store.identityKeyStore.getLocalRegistrationID()
        let identity = PreKeyBundle.Identity(
            key: key,
            registrationId: registrationId)
        try server.upload(identity: identity)
    }

    /**
     Store a new SignedPreKey on the server (deleting the old one).
     - Note: A new key should be uploaded every few days.
     - returns: `True` on success
     */
    public func uploadNewSignedPreKey() throws {
        let identity = try store.identityKeyStore.getIdentityKey()
        let id = store.signedPreKeyStore.lastId &+ 1
        let timestamp = UInt64(Date().timeIntervalSince1970)

        let signedKey = try SignalCrypto.generateSignedPreKey(
            identitykeyPair: identity,
            id: id,
            timestamp: timestamp)
        
        let signedPreKey = PreKeyBundle.SignedPreKey(
            id: id,
            key: signedKey.keyPair.publicKey,
            signature: signedKey.signature)

        try server.upload(signedPreKey: signedPreKey)
        try store.signedPreKeyStore.store(signedPreKey: signedKey)
    }

    /**
     Store a number of unsigned PreKeys on the server.
     - Note: These keys should be replenished as needed.
     - returns: `True` on success
     */
    public func uploadPreKeys() throws {
        let remaining = try server.preKeyCount()
        let count = preKeyMaxCount - remaining
        let start = store.preKeyStore.lastId &+ 1
        let keys = try SignalCrypto.generatePreKeys(start: start, count: count)
        let mappedKeys = keys.map { PreKeyBundle.PreKey(id: $0.id, key: $0.keyPair.publicKey) }
        try server.upload(preKeys: mappedKeys)
        try keys.forEach{ try store.preKeyStore.store(preKey: $0) }
    }

    /**
     Get a PreKeyBundle to create a new session with another client.
     - parameter address: The remote address for which to get the bundle.
     - returns: The PreKeyBundle for the recipient.
     */
    public func preKeyBundle(for address: SignalAddress) throws -> PreKeyBundle {
        return try server.preKeyBundle(for: address)
    }

    /**
     Upload a message to a recipient.
     - parameter message: The message to upload
     - parameter receiver: The intended recipient of the message
     - returns: `True` on success
     */
    public func upload(message: Data, for receiver: SignalAddress) throws {
        try server.upload(message: message, for: receiver)
    }

    /**
     Upload messages to a recipient.
     - parameter messages: The messages to upload
     - parameter receiver: The intended recipient of the messages
     - returns: `True` on success
     */
    public func upload(messages: [Data], for receiver: SignalAddress) throws {
        try server.upload(messages: messages, for: receiver)
    }

    public func messages() throws -> [SignalAddress : [Data]] {
        return try server.messages()
    }
}
