//
//  SignalSession.swift
//  SignalCommunication
//
//  Created by User on 15.11.17.
//

import Foundation

/**
 A session is used to handle all message processing and encryption/decryption
 of incoming and outgoing messages.
 */
public final class SignalSession<Context: SignalProtocolStoreContext> where Context.Address == SignalAddress {

    /// The storage for the keys and other data
    private let store: Context

    /// The address of the remote party
    private var remoteAddress: Context.Address

    /**
     Establish a new session before processing a PreKeyMessage, or to encrypt/decrypt in an already existing session.
     - parameter address: The address of the remote client
     - parameter
     */
    public init(for address: Context.Address, store: Context) {
        self.remoteAddress = address
        self.store = store
    }

    /**
     Establish a session by processing a PreKeyBundle.
     - parameter address: The address of the remote client
     - parameter preKeyBundle: The pre key bundle of the remote
     - throws: `SignalError` errors
     */
    public convenience init(for address: Context.Address, with preKeyBundle: PreKeyBundle, in store: Context) throws {
        self.init(for: address, store: store)
        try process(preKeyBundle)
    }

    /**
     Establish a session by processing a PreKeyBundle.
     - parameter preKeyBundle: The pre key bundle of the remote
     - throws: `SignalError` errors
     */
    private func process(_ preKeyBundle: PreKeyBundle) throws {
        let bundle = SessionPreKeyBundle(
            registrationId: preKeyBundle.identity.registrationId,
            deviceId: remoteAddress.deviceId,
            preKeyId: preKeyBundle.preKey?.id ?? 0,
            preKeyPublic: preKeyBundle.preKey?.key,
            signedPreKeyId: preKeyBundle.signedPreKey.id,
            signedPreKeyPublic: preKeyBundle.signedPreKey.key,
            signedPreKeySignature: preKeyBundle.signedPreKey.signature,
            identityKey: preKeyBundle.identity.key)

        let builder = SessionBuilder<Context>(remoteAddress: remoteAddress, store: store)
        try builder.process(preKeyBundle: bundle)
    }

    /**
     Decrypt a message.
     - parameter message: The serialized message
     - returns: The decrypted message
     - throws: `SignalError` errors
     */
    public func decrypt(_ message: Data) throws -> Data {
        guard message.count > 1, let type = CipherTextType(rawValue: message[0]) else {
            throw SignalError(.invalidMessage, "Missing data or unknown message type")
        }
        let data = message.advanced(by: 1)

        let cipher = SessionCipher(store: store, remoteAddress: self.remoteAddress)

        switch type {
        case .preKey:
            return try decrypt(preKeyMessage: data, cipher: cipher)
        case .signal:
            return try decrypt(signalMessage: data, cipher: cipher)
        case .senderKey, .senderKeyDistribution:
            // For these types use GroupSession.decrypt()
            throw SignalError(.invalidMessage, "Message must be PreKeyMessage or SignalMessage")
        }
    }

    /**
     Decrypt a PreKeySignalMessage.
     - parameter data: The serialized message
     - parameter cipher: The SessionCipher to decrypt
     - returns: The decrypted message
     - throws: `SignalError` errors
     */
    private func decrypt(preKeyMessage data: Data, cipher: SessionCipher<Context>) throws -> Data {
        let preKeyMessage = try PreKeySignalMessage(from: data)
        return try cipher.decrypt(preKeySignalMessage: preKeyMessage)
    }

    /**
     Decrypt a SignalMessage.
     - parameter data: The serialized message
     - parameter cipher: The SessionCipher to decrypt
     - returns: The decrypted message
     - throws: `SignalError` errors
    */
    private func decrypt(signalMessage data: Data, cipher: SessionCipher<Context>) throws -> Data {
        let signalMessage = try SignalMessage(from: data)
        return try cipher.decrypt(signalMessage: signalMessage)
    }

    /**
     Encrypt a message.
     - parameter data: The message to encrypt
     - returns: The encrypted message
     - throws: `SignalError` errors
     */
    public func encrypt(_ data: Data) throws -> Data {
        let cipher = SessionCipher(store: store, remoteAddress: self.remoteAddress)
        let ciphertext = try cipher.encrypt(paddedMessage: data)
        let firstByte = Data([ciphertext.type.rawValue])
        return firstByte + ciphertext.data
    }
}
