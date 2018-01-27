//
//  SignalProtocolStoreContext.swift
//  SignalProtocolSwift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


/**
 Provide all local storage delegates.
 */
public protocol SignalProtocolStoreContext {

    associatedtype Address

    associatedtype GroupAddress

    associatedtype IdentityKeyStore: IdentityKeyStoreDelegate where IdentityKeyStore.Address == Address

    associatedtype SenderKeyStore: SenderKeyStoreDelegate where SenderKeyStore.Address == GroupAddress

    associatedtype SessionStore: SessionStoreDelegate where SessionStore.Address == Address

    /// The Identity Key store that stores the records for the identity key module
    var identityKeyStore: IdentityKeyStore { get }

    /// The Pre Key store that stores the records for the pre key module
    var preKeyStore: PreKeyStoreDelegate { get }

    /// The Sender Key store that stores the records for the sender key module
    var senderKeyStore: SenderKeyStore { get }

    /// The Session store that stores the records for the session module
    var sessionStore: SessionStore { get }

    /// The Signed Pre Key store that stores the records for the signed pre key module
    var signedPreKeyStore: SignedPreKeyStoreDelegate { get }

}

extension SignalProtocolStoreContext {

    /**
     Create a signed pre key with the given id and store it.
     - note: The following errors can be thrown:
     - `noRandomBytes`, if the crypto provider can't provide random bytes.
     - `curveError`, if no public key could be created from the random private key.
     - `invalidLength`, if the public key is more than 256 or 0 byte.
     - `invalidSignature`, if the message could not be signed.
     - `storageError`, if the identity key could not be accessed, or if the key could not be stored
     - `invalidProtobuf`, if the key could not be serialized
     - parameter id: The id of the signed pre key
     - parameter timestamp: The timestamp of the key, defaults to seconds since 1970
     - returns: The generated signed pre key
     - throws: `SignalError`
    */
    public func createSignedPrekey(id: UInt32, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) throws -> SessionSignedPreKey {
        let privateKey = try identityKeyStore.getIdentityKey().privateKey
        let key = try SignalCrypto.generateSignedPreKey(
            identityKey: privateKey,
            id: id, timestamp: timestamp)

        try signedPreKeyStore.store(signedPreKey: key)
        return key
    }

    /**
     Create a number of pre keys and store them.
     - note: The following errors can be thrown:
     - `noRandomBytes` if the crypto provider can't provide random bytes.
     - `curveError` if no public key could be created from a random private key.
     - `storageError`, if the keys could not be stored
     - `invalidProtoBuf`, if the keys could not be serialized
     - parameter start: the starting pre key ID, inclusive.
     - parameter count: the number of pre keys to generate.
     - returns: The pre keys
     - throws: `SignalError` errors
    */
    public func createPreKeys(start: UInt32, count: Int) throws -> [SessionPreKey] {
        let keys = try SignalCrypto.generatePreKeys(start: start, count: count)
        for key in keys {
            try preKeyStore.store(preKey: key)
        }
        return keys
    }

    /**
     Create a PreKeyBundle for the given ids.

     - note: Possible errors:
     - `invalidId`, if no key with the right id exists
     - `invalidProtoBuf`, if key data is corrupt or missing
     - `storageError`, if the registrationID or identity key can't be accessed
     - parameter deviceId: The id of the device
     - parameter preKeyId: The id of the pre key (must be stored)
     - parameter signedPreKeyId: The id of the signed pre key (must be stored)
     - returns: The pre key bundle
     - throws: `SignalError` errors
    */
    public func createPreKeyBundle(deviceId: UInt32, preKeyId: UInt32, signedPreKeyId: UInt32) throws -> SessionPreKeyBundle {

        return SessionPreKeyBundle(
            registrationId: try identityKeyStore.getLocalRegistrationID(),
            deviceId: deviceId,
            preKey: try preKeyStore.preKey(for: preKeyId),
            signedPreKey: try signedPreKeyStore.signedPreKey(for: signedPreKeyId),
            identityKey: try identityKeyStore.getIdentityKey().publicKey)
    }
}
