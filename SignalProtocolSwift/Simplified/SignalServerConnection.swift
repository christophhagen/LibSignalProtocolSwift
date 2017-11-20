//
//  SignalServerConnection.swift
//  SignalCommunication-iOSTests
//
//  Created by User on 16.11.17.
//

import Foundation

public final class SignalServerConnection {

    private static let preKeyMaxCount = 10

    private let store: SignalProtocolStoreContext

    private let server: SignalServer

    init(store: SignalProtocolStoreContext, server: SignalServer) {
        self.store = store
        self.server = server
    }

    /**
     Store the identity of the local client on the server.
     */
    public func uploadIdentity() throws {
        let address = server.ownAddress
        let key = try store.getIdentityKey().publicKey
        let registrationId = try store.getLocalRegistrationID()
        let identity = PreKeyBundle.Identity(
            key: key,
            registrationId: registrationId,
            deviceId: address.deviceId)
        try server.upload(identity: identity)
    }

    /**
     Store a new SignedPreKey on the server (deleting the old one).
     - Note: A new key should be uploaded every few days.
     - returns: `True` on success
     */
    public func uploadNewSignedPreKey() throws {
        let identity = try store.getIdentityKey()
        let id = store.lastSignedPreKeyId &+ 1
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
        try store.store(signedPreKey: signedKey)
    }

    /**
     Store a number of unsigned PreKeys on the server.
     - Note: These keys should be replenished as needed.
     - returns: `True` on success
     */
    public func uploadPreKeys() throws {
        let remaining = try server.preKeyCount()
        let count = SignalServerConnection.preKeyMaxCount - remaining
        let start = store.lastPreKeyId + 1
        let keys = try SignalCrypto.generatePreKeys(start: start, count: count)
        let mappedKeys = keys.values.map { PreKeyBundle.PreKey(id: $0.id, key: $0.keyPair.publicKey) }
        try server.upload(preKeys: mappedKeys)
        try keys.values.forEach{ try store.store(preKey: $0) }
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
