//
//  SignalInterface.swift
//  TestC
//
//  Created by User on 23.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 This class provides the only active interaction with the Signal Protocol API.

 Create an instance and provide the required presistent stores to save the required
 Key material. It is then possible to create sessions with recipients as well as
 encrypt and decrypt messages. The normal procedure is as follows:

 - Alice creates a Pre Key Bundle and a number of Pre Keys
 - Alice uploads the created data to a server
 - Bob retrieves a copy of the Pre Key Bundle and one of the Pre Keys
 - Bob creates a session with the Key material
 - Bob encrypts a message and sends it to Alice.
 - Alice decrypts the initial message and creates her session.
 - Both parties can now send fully encrypted messages.
 */
class SignalInterface {

    // MARK: Internal variables

    /// The shared global Signal Context
    private static var sharedContext:  UnsafeMutablePointer<signal_context>! = nil

    /// The shared global Signal Context
    static var context: UnsafeMutablePointer<signal_context>! {
        if SignalInterface.sharedContext == nil {
            try? createGlobalContext()
        }
        return SignalInterface.sharedContext
    }

    /// The shared global Signal Context
    var context: UnsafeMutablePointer<signal_context>!  {
        return SignalInterface.context
    }



    // MARK: Persistent stores

    /// Number of instances
    private static var instanceCount = 0

    /// The protocol store context for the Signal C Library
    private var protocolStore: OpaquePointer!

    /// The Identity Key store that relays the callbacks to the identity key module
    private let identityKeyStore: IdentityKeyStore

    /// The Pre Key store that relays the callbacks to the pre key module
    private let preKeyStore: PreKeyStore

    /// The Sender Key store that relays the callbacks to the sender key module
    private let senderKeyStore: SenderKeyStore

    /// The Session store that relays the callbacks to the session module
    private let sessionStore: SessionStore

    /// The Signed Pre Key store that relays the callbacks to the signed pre key module
    private let signedPreKeyStore: SignedPreKeyStore



    // MARK: Initialization

    /**
     Initialize a `SignalInterface` with a `KeyStoreDelegate` that provides all
     necessary stores.
     - Note: Should not fail during normal operations
     - parameter keyStore: The implementation that provides the storage capabilities
     */
    convenience init?(keyStore: KeyStoreDelegate?) {
        guard let store = keyStore else {
            SignalInterface.log(level: .warning, message: "No Key Store provided for Signal Interface")
            return nil
        }
        self.init(identityKeyStore: store.identityKeyStore,
                  preKeyStore: store.preKeyStore,
                  senderKeyStore: store.senderKeyStore,
                  sessionStore: store.sessionStore,
                  signedPreKeyStore: store.signedPreKeyStore)
    }

    /**
     Initialize a `SignalInterface` with all the necessary storage implementations. Create a single
     instance of this class for all operations.

     - Note: Should not fail during normal operations
     - parameter identityKeyStore: The persistent storage for identity keys
     - parameter preKeyStore: The persistent storage for pre keys
     - parameter senderKeyStore: The persistent storage for sender keys
     - parameter sessionStore: The persistent storage for sessions
     - parameter signedPreKeyStore: The persistent storage for signed pre keys
     */
    init?(identityKeyStore: IdentityKeyStoreDelegate,
         preKeyStore: PreKeyStoreDelegate,
         senderKeyStore: SenderKeyStoreDelegate,
         sessionStore: SessionStoreDelegate,
         signedPreKeyStore: SignedPreKeyStoreDelegate) {

        /** Make sure the global context is created */
        if SignalInterface.sharedContext == nil {
            do {
                try SignalInterface.createGlobalContext()
            } catch {
                SignalInterface.log(level: .error, message: "Could not create global Signal Context")
                return nil
            }
        }

        /* Create the protocol store */
        var protocolContext: OpaquePointer? = nil
        let result = withUnsafeMutablePointer(to: &protocolContext) { signal_protocol_store_context_create($0, SignalInterface.sharedContext) }

        protocolStore = protocolContext!
        guard let iKS = IdentityKeyStore(with: protocolStore, delegate: identityKeyStore) else {
            SignalInterface.log(level: .error, message: "Could not register Identity Key Store Delegate")
            return nil
        }
        self.identityKeyStore = iKS

        guard let pKS = PreKeyStore(with: protocolStore, delegate: preKeyStore) else {
            SignalInterface.log(level: .error, message: "Could not register Pre Key Store Delegate")
            return nil
        }
        self.preKeyStore = pKS

        guard let sKS = SenderKeyStore(with: protocolStore, delegate: senderKeyStore) else {
            SignalInterface.log(level: .error, message: "Could not register Sender Key Store Delegate")
            return nil
        }
        self.senderKeyStore = sKS

        guard let sS = SessionStore(with: protocolStore, delegate: sessionStore) else {
            SignalInterface.log(level: .error, message: "Could not register Session Store Delegate")
            return nil
        }
        self.sessionStore = sS

        guard let sPKS = SignedPreKeyStore(with: protocolStore, delegate: signedPreKeyStore) else {
            SignalInterface.log(level: .error, message: "Could not register Signed Pre Key Store Delegate")
            return nil
        }
        self.signedPreKeyStore = sPKS

        // Wait with destruction until all properties are initialized
        guard result == 0, protocolContext != nil else {
            if SignalInterface.instanceCount == 0 {
                destroyGlobalContext()
            }
            return nil
        }
        SignalInterface.instanceCount += 1
    }

    /**
     Destroy the protocol context and possibly the global context
     */
    deinit {
        SignalInterface.instanceCount -= 1
        if SignalInterface.instanceCount == 0 && context != nil {
            destroyGlobalContext()
        }

        signal_protocol_store_context_destroy(protocolStore)
    }



    // MARK: Message Encryption

    /**
     Encrypt a message for a recipient.
     - parameter text: The text to encrypt
     - parameter address: The address of the recipient
     - returns: The encrypted message, or nil on error
     */
    func encrypt(text: String, to address: CHAddress) -> EncryptedData? {
        do {
            return try encrypt(message: [UInt8](text.utf8), to: address)
        } catch {
            SignalInterface.log(level: .info, message: "Could not encrypt text message")
            return nil
        }
    }

    /**
     Create a session and encrypt an initial message.
     - parameter string: The initial text to encrypt
     - parameter address: The address of the recipient
     - parameter preKeyBundle: The serialized Pre Key Bundle from the recipient
     - parameter preKey: A serialized Pre Key from the recipient
     - returns: The encrypted message
     */
    func encryptInitial(text: String, to address: CHAddress, with preKeyBundle: PreKeyBundle, and preKey: PreKey) -> EncryptedData? {
        do {
            return try encryptInitial([UInt8](text.utf8), to: address, with: preKeyBundle, and: preKey)
        } catch {
            SignalInterface.log(level: .info, message: "Could not encrypt initial text message")
            return nil
        }
    }

    /**
     Encrypt a message for a recipient.
     - parameter message: The message to encrypt
     - parameter address: The address of the recipient
     - returns: The encrypted message
     - throws: SignalError
     */
    func encrypt(message: UnencryptedData, to address: CHAddress) throws -> EncryptedData {

        guard let recipientID = address.recipientID.cString(using: String.Encoding.utf8) else {
            throw SignalError(type: .invalidRecipientID, message: "RecipientID is not a valid UTF8 String")
        }
        var storedAddress = signal_protocol_address(name: UnsafePointer(recipientID), name_len: recipientID.count, device_id: Int32(address.deviceID))

        var sessionCipher: OpaquePointer? = nil
        var result = withUnsafePointer(to: &storedAddress) { ptr in
            withUnsafeMutablePointer(to: &sessionCipher) {
                session_cipher_create($0, protocolStore, ptr, context)
            }
        }
        guard result == 0 else {
            throw SignalError(type: .noSession, message: "No session exists for the given address", code: result)
        }

        var encryptedMessage: OpaquePointer? = nil
        result = withUnsafeMutablePointer(to: &encryptedMessage) { pointer in
            return session_cipher_encrypt(sessionCipher, UnsafePointer(message), message.count, pointer)
        }

        session_cipher_free(sessionCipher)

        guard result == 0 else {
            throw SignalError(type: .encryptFailed, message: "Could not encrypt message for given address", code: result)
        }

        let buffer = ciphertext_message_get_serialized(encryptedMessage)
        let output = Array(UnsafeBufferPointer(start: signal_buffer_data(buffer), count: signal_buffer_len(buffer)))
        signal_type_unref(UnsafeMutablePointer<signal_type_base>(encryptedMessage))
        return output
    }

    /**
     Create a session and encrypt an initial message.
     - parameter message: The initial message to encrypt
     - parameter address: The address of the recipient
     - parameter preKeyBundle: The serialized Pre Key Bundle from the recipient
     - parameter preKey: A serialized Pre Key from the recipient
     - returns: The encrypted message
     - throws: SignalError
     */
    func encryptInitial(_ message: UnencryptedData, to address: CHAddress, with preKeyBundle: PreKeyBundle, and preKey: PreKey) throws -> PreKeyMessage {
        guard let recipientID = address.recipientID.cString(using: String.Encoding.utf8) else {
            throw SignalError(type: .invalidRecipientID, message: "RecipientID is not a valid UTF8 String")
        }
        var storedAddress = signal_protocol_address(name: UnsafePointer(recipientID), name_len: recipientID.count, device_id: Int32(address.deviceID))

        var sessionBuilder: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &storedAddress) { addressPointer in
            return withUnsafeMutablePointer(to: &sessionBuilder) { session_builder_create($0, protocolStore, addressPointer, context) }
        }
        guard result == 0 else {
            throw SignalError(type: .noSession, message: "Could not create SessionBuilder for given address", code: result)
        }

        var bundle: OpaquePointer? = nil
        do {
            bundle = try createSessionPreKeyBundle(from: preKeyBundle, and: preKey)
        } catch {
            session_builder_free(sessionBuilder)
            throw error
        }

        result = session_builder_process_pre_key_bundle(sessionBuilder, bundle)

        session_pre_key_bundle_destroy(UnsafeMutablePointer<signal_type_base>(bundle))
        session_builder_free(sessionBuilder)

        guard result == 0 else {
            throw SignalError(type: .invalidPreKeyBundle, message: "Could not process Pre Key Bundle", code: result)
        }
        return try encrypt(message: message, to: address)
    }

    /**
     Create a Session Pre Key Bundle from a serialized Pre Key Bundle and Pre Key.
     - note: The returned pointer needs to be freed through `session_pre_key_bundle_destroy()`
     - parameter bundle: The serialized Pre Key Bundle
     - parameter preKey: The serialized Pre Key
     - returns: A pointer to a `session_pre_key_bundle`
     - throws: SignalError
     */
    private func createSessionPreKeyBundle(from bundle: PreKeyBundle, and preKey: PreKey) throws -> OpaquePointer {
        guard bundle.count == 142, preKey.count == 37 else {
            throw SignalError(type: .invalidPreKeyBundle, message: "Wrong Bundle/Key length: \(bundle.count),\(preKey.count)")
        }
        let localRegistrationID = UInt32(from: Array(bundle[0..<4]))
        let deviceID = UInt32(from: Array(bundle[4..<8]))
        let signedPreKeyID = UInt32(from: Array(bundle[8..<12]))

        /** Get Signed Pre Key from bundle */
        var buffer = signal_buffer_create(UnsafePointer(bundle).advanced(by: 12), 33)
        var spkpp: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &spkpp) { ec_public_key_deserialize($0, buffer) }
        signal_buffer_free(buffer)
        guard result == 0, spkpp != nil else {
            throw SignalError(type: .corruptKey, message: "Invalid Signed Pre Key", code: result)
        }

        /** Get Identity Key from bundle */
        buffer = signal_buffer_create(UnsafePointer(bundle).advanced(by: 45), 33)
        var ikpp: OpaquePointer? = nil
        result = withUnsafeMutablePointer(to: &ikpp) { ec_public_key_deserialize($0, buffer) }
        signal_buffer_free(buffer)
        guard result == 0, ikpp != nil else {
            throw SignalError(type: .corruptKey, message: "Invalid Identity Key", code: result)
        }

        /** Get Pre Key from bundle */
        buffer = signal_buffer_create(UnsafePointer(preKey).advanced(by: 4), 33)
        var spkp: OpaquePointer? = nil
        result = withUnsafeMutablePointer(to: &spkp) { ec_public_key_deserialize($0, buffer) }
        guard result == 0, spkp != nil else {
            throw SignalError(type: .corruptKey, message: "Invalid Pre Key", code: result)
        }

        let preKeyID = UInt32(from: Array(preKey[0..<4]))

        var preKeyBundle: OpaquePointer? = nil
        result = withUnsafeMutablePointer(to: &preKeyBundle) {
            session_pre_key_bundle_create($0, localRegistrationID, Int32(deviceID), preKeyID, spkp, signedPreKeyID, spkpp, UnsafePointer(bundle).advanced(by: 78), 64, ikpp)
        }
        guard result == 0, preKeyBundle != nil else {
            throw SignalError(type: .invalidPreKeyBundle, message: "Could not process Pre Key Bundle", code: result)
        }
        return preKeyBundle!
    }



    // MARK: Decryption

    /**
     Decrypt a message from a sender.
     - parameter message: The encrypted message
     - parameter address: The address of the sender
     - parameter trustNewIdentity: `True`, if the sender should be trusted when the identity key changed
     - returns: The decrypted text
     */
    func decryptText(_ message: EncryptedData, from address: CHAddress, trustNewIdentity: Bool = false) -> String? {
        do {
            let plaintext = try decrypt(message, from: address, trustNewIdentity: trustNewIdentity)
            guard let string = String(bytes: plaintext, encoding: .utf8) else {
                throw SignalError(type: .notTextMessage, message: "Could not create String from decrypted message")
            }
            return string
        } catch let error as SignalError {
            print(error)
            return nil
        } catch {
            SignalInterface.log(level: .info, message: "Could not decrypt given message as text")
            return nil
        }
    }

    /**
     Decrypt a message from a sender.
     - parameter message: The encrypted message
     - parameter address: The address of the sender
     - parameter trustNewIdentity: `True`, if the sender should be trusted when the identity key changed
     - returns: The decrypted message
     - throws: SignalError
     */
    func decrypt(_ message: EncryptedData, from address: CHAddress, trustNewIdentity: Bool = false) throws -> UnencryptedData {
        do {
            /* First try to decrypt as normal message */
            let decrypted = try decryptInternal(message, from: address, isInitialMessage: false)
            return decrypted
        } catch let error as SignalError {
            if error.type != .wrongMessageType {
                throw error
            }
        } catch {
            throw error
        }

        /** Try to decrypt as Pre Key Message */
       let decrypted = try decryptInternal(message, from: address, isInitialMessage: true, trustNewIdentity: trustNewIdentity)
       return decrypted
    }

    /**
     Internal function to decrypt a message.
     - parameter message: The ciphertext of the message
     - parameter address: The address of the sender
     - parameter isInitialMessage: `True` if the message is a Pre Key Message
     - parameter trustNewIdentity: `True`, if the sender should be trusted when the identity key has changed
     - returns: The decrypted message
     - throws: SignalError
     */
    private func decryptInternal(_ message: EncryptedData, from address: CHAddress, isInitialMessage: Bool = false, trustNewIdentity: Bool = false) throws -> UnencryptedData {

        guard let recipientID = address.recipientID.cString(using: String.Encoding.utf8) else {
            throw SignalError(type: .invalidRecipientID, message: "RecipientID is not a valid UTF8 String")
        }
        var storedAddress = signal_protocol_address(name: UnsafePointer(recipientID), name_len: recipientID.count, device_id: Int32(address.deviceID))

        var deserializedMessage: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &deserializedMessage) { (pointer: UnsafeMutablePointer<OpaquePointer?>?) -> Int32 in
            if isInitialMessage {
                return pre_key_signal_message_deserialize(pointer, UnsafePointer(message), message.count, context)
            } else {
                return signal_message_deserialize(pointer, UnsafePointer(message), message.count, context)
            }
        }

        guard result == 0 else {
            throw SignalError(type: .wrongMessageType, message: "Could not deserialize Message", code: result)
        }

        if isInitialMessage && trustNewIdentity {
            result = withUnsafePointer(to: &storedAddress) { addressPointer in
                return signal_protocol_identity_save_identity(protocolStore, addressPointer, pre_key_signal_message_get_identity_key(deserializedMessage))
            }
            guard result == 0 else {
                throw SignalError(type: .keyStoreFailure, message: "Could not save new identity key", code: result)
            }
        }

        var sessionCipher: OpaquePointer? = nil
        result = withUnsafePointer(to: &storedAddress) { addressPointer in
            return withUnsafeMutablePointer(to: &sessionCipher) { session_cipher_create($0, protocolStore, addressPointer, context) }
        }

        guard result == 0 else {
            signal_type_unref(UnsafeMutablePointer<signal_type_base>(deserializedMessage))
            throw SignalError(type: .noSession, message: "Could not create SessionCipher", code: result)
        }

        var buffer: UnsafeMutablePointer<signal_buffer>? = nil
        result = withUnsafeMutablePointer(to: &buffer) { pointer in
            if isInitialMessage {
                return session_cipher_decrypt_pre_key_signal_message(sessionCipher, deserializedMessage, nil, pointer)
            } else {
                return session_cipher_decrypt_signal_message(sessionCipher, deserializedMessage, nil, pointer)
            }
        }

        signal_type_unref(UnsafeMutablePointer<signal_type_base>(deserializedMessage))
        session_cipher_free(sessionCipher)

        guard result == 0 else {
            if result == SG_ERR_UNTRUSTED_IDENTITY {
                throw SignalError(type: .untrustedIdentity, message: "A session for the remote client exists with a different identity")
            }
            throw SignalError(type: .decryptFailed, message: "Could not decrypt message", code: result)
        }

        let length = signal_buffer_len(buffer)
        let data = signal_buffer_data(buffer)
        let output = Array(UnsafeBufferPointer(start: data, count: length))
        signal_buffer_free(buffer)
        return output
    }



    // MARK: First launch

    /**
     Generate an identity key pair. Clients should only do this once, at install time.

     - returns: The serialized identity key pair, or nil on error.
     */
    static func generateIdentityKeyPair() -> IdentityKeyPair? {
        guard context != nil else {
            log(level: .error, message: "No global Signal Context")
            return nil
        }

        var identityKeyPair: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &identityKeyPair) { pointer in
            return signal_protocol_key_helper_generate_identity_key_pair(pointer, context)
        }
        guard result == 0 else {
            log(level: .error, message: "Could not create Identity Key Pair: \(result)")
            return nil
        }

        var buffer: UnsafeMutablePointer<signal_buffer>? = nil
        result = withUnsafeMutablePointer(to: &buffer) { pointer in
            return ratchet_identity_key_pair_serialize(pointer, identityKeyPair);
        }

        ratchet_identity_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(identityKeyPair));
        guard result == 0 else {
            log(level: .error, message: "Could not serialize Identity Key Pair: \(result)")
            return nil
        }

        let key = Array(UnsafeMutableBufferPointer(start: signal_buffer_data(buffer),
                                                   count: signal_buffer_len(buffer)))

        signal_buffer_free(buffer)
        return key
    }

    /**
     Generate a registration ID. Clients should only do this once, at install time.

     - Throws: `SignalError`: `noGlobalContext`, if no global context exists.
     `failGenerateRegistrationID`, if the ID could not be created
     - Returns: the generated registration ID on success, or nil on failure
     */
    static func generateRegistrationID() -> Int? {
        guard context != nil else {
            log(level: .error, message: "No global Signal Context")
            return nil
        }

        var registrationID: UInt32 = 0
        let result = withUnsafeMutablePointer(to: &registrationID) { signal_protocol_key_helper_generate_registration_id($0, 0, context) }
        guard result == 0, registrationID != 0 else {
            log(level: .error, message: "Could not create Local Registration ID: \(result)")
            return nil
        }
        return Int(registrationID)
    }



    // MARK: Pre Keys and Pre Key Bundles

    /**
     Generate a Pre Key Bundle and a Pre Key. This function is mostly convenient for testing. To create a larger number of Pre Keys use `generatePreKeys(count:)`.
     - parameter deviceID: The device ID of the client
     - parameter signedPreKeyID: The ID of the signed pre key
     - returns: A tuple with the Pre Key Bundle and the Pre Key
     */
    func generatePreKeyBundleAndPreKey(deviceID: DeviceID, signedPreKeyID: SignedPreKeyID) -> (bundle: PreKeyBundle, preKey: PreKey)? {
        do {
            let bundle = try generatePreKeyBundle(deviceID: deviceID, signedPreKeyID: signedPreKeyID)
            let preKey = try generatePreKey()
            return (bundle, preKey)
        } catch let error as SignalError {
            SignalInterface.log(level: .error, message: #function + (error.message ?? "No description"))
        } catch {
            SignalInterface.log(level: .error, message: #function + error.localizedDescription)
        }
        return nil
    }

    /**
     Generate a Pre Key Bundle.
     - note: If no Signed Pre Key with the ID exists, a new one will be created.
     - parameter deviceID: The device ID of the sender
     - parameter signedPreKeyID: The ID of the signed Pre Key to use
     - returns: The serialized Pre Key Bundle
     - throws: SignalError
     */
    func generatePreKeyBundle(deviceID: DeviceID, signedPreKeyID: SignedPreKeyID) throws -> PreKeyBundle {
        /** Get the local registration ID from the store */
        let localRegistrationID = identityKeyStore.delegate.localRegistrationID

        /** Get the Identity Key Pair from the store */
        var identityKeyPair: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &identityKeyPair) { signal_protocol_identity_get_key_pair(protocolStore, $0) }
        guard result == 0, identityKeyPair != nil else {
            throw SignalError(type: .keyStoreFailure, message: "Could not get Identity", code: result)
        }

        let signedPreKey = try loadSignedPreKey(id: signedPreKeyID, identityKeyPair: identityKeyPair!)
        let signedPreKeyPair = session_signed_pre_key_get_key_pair(signedPreKey)
        let signedPreKeySignature = session_signed_pre_key_get_signature(signedPreKey)
        let signedPreKeySignatureLength = session_signed_pre_key_get_signature_len(signedPreKey)

        let lrid = UInt32(localRegistrationID).arrayUInt8
        let did = UInt32(deviceID).arrayUInt8
        let spkid = signedPreKeyID.arrayUInt8
        let spks = Array(UnsafeBufferPointer(start: signedPreKeySignature, count: signedPreKeySignatureLength))

        var spkpp: UnsafeMutablePointer<signal_buffer>? = nil
        result = withUnsafeMutablePointer(to: &spkpp) { ec_public_key_serialize($0, ec_key_pair_get_public(signedPreKeyPair)) }
        let spkpps = Array(UnsafeMutableBufferPointer(start: signal_buffer_data(spkpp), count: signal_buffer_len(spkpp)))
        signal_buffer_free(spkpp)

        var ikpp: UnsafeMutablePointer<signal_buffer>? = nil
        result = withUnsafeMutablePointer(to: &ikpp) { ec_public_key_serialize($0, ratchet_identity_key_pair_get_public(identityKeyPair)) }
        let ikpps = Array(UnsafeMutableBufferPointer(start: signal_buffer_data(ikpp), count: signal_buffer_len(ikpp)))
        signal_buffer_free(ikpp)

        session_signed_pre_key_destroy(UnsafeMutablePointer<signal_type_base>(signedPreKey))
        ratchet_identity_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(identityKeyPair))
        return lrid + did + spkid + spkpps + ikpps + spks
    }

    /**
     Generate a new pre key and add it to the store.
     - returns: The serialized Pre Key
     - throws: SignalError
     */
    func generatePreKey() throws -> PreKey {
        /** Generate a new Pre Key Pair */
        var preKeyPair: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &preKeyPair) { curve_generate_key_pair(context, $0) }
        guard result == 0 else {
            throw SignalError(type: .noKeyCreated, message: "Could not create Pre Key Pair", code: result)
        }

        let preKeyID = preKeyStore.delegate.nextPreKeyID

        /* Serialize the Pre Key for storage */
        var preKey: OpaquePointer? = nil
        result = withUnsafeMutablePointer(to: &preKey) { session_pre_key_create($0, UInt32(preKeyID), preKeyPair) }
        guard result == 0 else {
            ec_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(preKeyPair))
            throw SignalError(type: .noKeyCreated, message: "Could not create Session Pre Key", code: result)
        }

        /** Store the Pre Key */
        result = signal_protocol_pre_key_store_key(protocolStore, preKey)
        guard result == 0 else {
            session_pre_key_destroy(UnsafeMutablePointer<signal_type_base>(preKey))
            signal_type_unref(UnsafeMutablePointer<signal_type_base>(preKeyPair))
            throw SignalError(type: .keyStoreFailure, message: "Could not store Pre Key", code: result)
        }

        /** Create serialized version */
        var buffer: UnsafeMutablePointer<signal_buffer>? = nil
        result = withUnsafeMutablePointer(to: &buffer) { ec_public_key_serialize($0, ec_key_pair_get_public(preKeyPair)) }
        session_pre_key_destroy(UnsafeMutablePointer<signal_type_base>(preKey))
        signal_type_unref(UnsafeMutablePointer<signal_type_base>(preKeyPair))
        guard result == 0 else {
            throw SignalError(type: .corruptKey, message: "Could not serialize Pre Key", code: result)
        }

        preKeyStore.delegate.setNextPreKeyID(UInt32(truncatingIfNeeded: Int(preKeyID) + 1))
        return UInt32(preKeyID).arrayUInt8 + Array(UnsafeBufferPointer(start: signal_buffer_data(buffer), count: signal_buffer_len(buffer)))
    }

    /**
     Generate a number pre keys with a given pre key ID to start with. This will store the
     generated pre keys in the pre key store.

     Pre key IDs are shorts, so they will eventually be repeated. Clients should store pre keys
     in a circular buffer, so that they are repeated as infrequently as possible.

     - parameter startID: The first pre key ID
     - parameter count: The number of pre keys to generate
     - throws: `SignalError`: `noGlobalContext`, if no global context exists.
     `failGeneratePreKeys`, if the pre key list could not be created.
     */
    func generatePreKeys(count: Int) throws -> [PreKeyID : PreKey] {

        let startID = preKeyStore.delegate.nextPreKeyID
        var head: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &head) { pointer in
            return signal_protocol_key_helper_generate_pre_keys(pointer, startID, UInt32(count), context)
        }
        guard result == 0 else {
            throw SignalError(type: .noKeyCreated, message: "No Pre Keys created", code: result)
        }

        var serializedKeys = [PreKeyID : PreKey]()

        var node = head
        while (node != nil) {
            let nodePointer = signal_protocol_key_helper_key_list_element(node)

            /** Save Pre Key in store */
            result = signal_protocol_pre_key_store_key(protocolStore, nodePointer)
            guard result == 0 else {
                signal_protocol_key_helper_key_list_free(head)
                throw SignalError(type: .keyStoreFailure, message: "Could not store Pre Key", code: result)
            }

            /** Create serialized version */
            var buffer: UnsafeMutablePointer<signal_buffer>? = nil
            result = withUnsafeMutablePointer(to: &buffer) {
                ec_public_key_serialize($0, ec_key_pair_get_public(session_pre_key_get_key_pair(nodePointer)))
            }
            guard result == 0 else {
                signal_protocol_key_helper_key_list_free(head)
                throw SignalError(type: .corruptKey, message: "Could not serialize Pre Key", code: result)
            }

            /** Append ID and convert to Array */
            let preKeyID = session_pre_key_get_id(nodePointer)
            let newKey = preKeyID.arrayUInt8 + Array(UnsafeBufferPointer(start: signal_buffer_data(buffer), count: signal_buffer_len(buffer)))
            signal_buffer_free(buffer)

            /** Add to output dictinoary */
            serializedKeys[preKeyID] = newKey
            node = signal_protocol_key_helper_key_list_next(node)
        }
        signal_protocol_key_helper_key_list_free(head)

        /* Make sure the Pre Key ID properly overflows */
        preKeyStore.delegate.setNextPreKeyID(UInt32(truncatingIfNeeded: Int(startID) + serializedKeys.count))
        return serializedKeys
    }

    // MARK: Signed Pre Keys

    /**
     Loads a Signed Pre Key from the store, or creates a new one.
     - parameter signedPreKeyID: The ID of the Signed Pre Key to load or create
     - parameter identityKeyPair: A Pointer to the Identity Key Pair of the client
     - returns: A pointer to the Signed Pre Key
     */
    private func loadSignedPreKey(id signedPreKeyID: UInt32, identityKeyPair: OpaquePointer) throws -> OpaquePointer {
        /** Create the signed pre key if it doesn't already exist */
        if signal_protocol_signed_pre_key_contains_key(protocolStore, signedPreKeyID) == 0 {
            try createSignedPreKey(id: signedPreKeyID, identityKeyPair: identityKeyPair)
        }
        var signedPreKeyComplete: OpaquePointer? = nil
        let result = withUnsafeMutablePointer(to: &signedPreKeyComplete) {
            signal_protocol_signed_pre_key_load_key(protocolStore, $0, signedPreKeyID)
        }
        guard result == 0, signedPreKeyComplete != nil else {
            throw SignalError(type: .keyStoreFailure, message: "Could not load Signed Pre Key", code: result)
        }
        return signedPreKeyComplete!
    }

    /**
     Creates a new Signed Pre Key and adds it to the Store.
     - parameter signedPreKeyID: The ID of the Signed Pre Key to generate
     - parameter identityKeyPair: A pointer to the Identity Key Pair of the client
     */
    private func createSignedPreKey(id signedPreKeyID: UInt32, identityKeyPair: OpaquePointer) throws {
        /** Generate a new Signed Pre Key Pair if the key doesn't exist yet */
        var signedPreKeyPair: OpaquePointer? = nil
        var result = withUnsafeMutablePointer(to: &signedPreKeyPair) { curve_generate_key_pair(context, $0) }
        guard result == 0, signedPreKeyPair != nil else {
            throw SignalError(type: .noKeyCreated, message: "Could not create Signed Pre Key", code: result)
        }

        /** Serialize the public part of the Signed Pre Key for the signature */
        var signedPreKeyPublicSerialized: UnsafeMutablePointer<signal_buffer>? = nil
        result = withUnsafeMutablePointer(to: &signedPreKeyPublicSerialized) {
            ec_public_key_serialize($0, ec_key_pair_get_public(signedPreKeyPair))
        }
        guard result == 0 else {
            ec_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(signedPreKeyPair))
            throw SignalError(type: .corruptKey, message: "Could not serialize Signed Pre Key", code: result)
        }

        /** Create the signature of the Signed Pre Key */
        var signedPreKeySignature: UnsafeMutablePointer<signal_buffer>? = nil
        result = withUnsafeMutablePointer(to: &signedPreKeySignature) {
            curve_calculate_signature(context, $0, ratchet_identity_key_pair_get_private(identityKeyPair), signal_buffer_data(signedPreKeyPublicSerialized), signal_buffer_len(signedPreKeyPublicSerialized))
        }

        // The serialized key is no longer needed
        signal_buffer_free(signedPreKeyPublicSerialized)

        guard result == 0 else {
            ec_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(signedPreKeyPair))
            throw SignalError(type: .invalidPreKeyBundle, message: "Could not calculate signature", code: result)
        }

        /* Serialize the Signed Pre Key for storage */
        var signedPreKeyRecord: OpaquePointer? = nil
        result = withUnsafeMutablePointer(to: &signedPreKeyRecord) { pointer in
            return session_signed_pre_key_create(pointer, signedPreKeyID, UInt64(time(nil)), signedPreKeyPair, signal_buffer_data(signedPreKeySignature), signal_buffer_len(signedPreKeySignature))
        }
        guard result == 0 else {
            signal_buffer_free(signedPreKeySignature)
            throw SignalError(type: .corruptKey, message: "Could not create Signed Pre Key", code: result)
        }

        /** Store the Signed Pre Key */
        result = signal_protocol_signed_pre_key_store_key(protocolStore, signedPreKeyRecord)
        signal_buffer_free(signedPreKeySignature)
        session_signed_pre_key_destroy(UnsafeMutablePointer<signal_type_base>(signedPreKeyRecord))
        guard result == 0 else {
            throw SignalError(type: .keyStoreFailure, message: "Could not store Signed Pre Key", code: result)
        }
    }



    // MARK: Global initialization

    /**
     Create the single global context when the first `SignalInterface` instance is created.
     This will also set the internal logging function, the cryptography provider and the locking
     functions.
      - throws: `SignalError` `failcreateGlobalContext`, `failSetLogFunction`, `failSetCryptoProvider`, `failSetLockingFunctions`
     */
    private static func createGlobalContext() throws {
        var context: UnsafeMutablePointer<signal_context>? = nil
        var result = withUnsafeMutablePointer(to: &context) { signal_context_create($0, nil) }

        guard result == 0, context != nil else {
            throw SignalError(type: .invalidRessource, message: "Could not create global context", code: result)
        }
        sharedContext = context

        result = signal_context_set_log_function(context, logInternalErrors)
        guard result == 0 else {
            signal_context_destroy(context);
            sharedContext = nil
            throw SignalError(type: .invalidRessource, message: "Could not set log function", code: result)
        }

        result = ch_crypto_provider_set(context)
        guard result == 0 else {
            signal_context_destroy(context);
            sharedContext = nil
            throw SignalError(type: .invalidRessource, message: "Could not set crypto provider", code: result)
        }

        result = ch_locking_functions_set(context)
        guard result == 0 else {
            signal_context_destroy(context);
            sharedContext = nil
            throw SignalError(type: .invalidRessource, message: "Could not set locking functions", code: result)
        }
    }

    /**
     Destroy the single global context if the last `SignalInterface` is destroyed.
     */
    private func destroyGlobalContext() {
        signal_context_destroy(SignalInterface.sharedContext);
        SignalInterface.sharedContext = nil
        ch_locking_functions_destroy()
    }

    /**
     Log debug messages to the console.
     - parameter level: The severity, see `SignalLogLevel`
     - parameter message: The text to be logged
     */
    fileprivate static func log(level: SignalLogLevel, message: String) {
        print(levelRepresentation(logLevel: level) + " " + message)
    }
}

/**
 This function receives internal logging from the Signal Protocol API. The output is currently
 simply printed to the console.

 - parameter level: The log level
 - parameter message: A pointer to the log entry
 - parameter length: The length of the string
 - parameter userData: A pointer to the user data
 */
private func logInternalErrors(level: Int32, message: UnsafePointer<Int8>?, length: Int, userData: UnsafeMutableRawPointer?) {
    guard message != nil else {
        return
    }
    guard let string = String(cString: message!, encoding: .utf8) else {
        print("[ERROR] Could not convert log message to String")
        return
    }
    let prefix = levelRepresentation(level: level)
    print(prefix + string)
}

/**
 Returns a textual representation of the log level.
 - parameter level: The log level [0..<5]
 - returns: The string representation
*/
private func levelRepresentation(level: Int32) -> String {
    guard let logLevel = SignalLogLevel(rawValue: level) else {
        return "[ NONE  ]"
    }
    return levelRepresentation(logLevel: logLevel)
}

/**
 Returns a textual representation for the log level enum.
 - parameter level: The log level, see `SignalLogLevel`
 - returns: The string representation
*/
private func levelRepresentation(logLevel: SignalLogLevel) -> String {
    switch logLevel {
    case .error:   return "[ ERROR ]"
    case .warning: return "[WARNING]"
    case .notice:  return "[ NOTICE]"
    case .info:    return "[ INFO  ]"
    case .debug:   return "[ DEBUG ]"
    }
}
