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
     Create a new identity key pair and store it.
     - note: Possible errors:
     - `noRandomBytes` if the crypto provider can't provide random bytes.
     - `curveError` if no public key could be created from the random private key.
     - `invalidProtoBuf` if the key pair could no be serialized
     - `storageError` if the data could not be saved
     - returns: The public key data for uploading to the server
     - throws: `SignalError` errors
     */
    public func createIdentityKey() throws -> Data {
        let keyPair = try KeyPair()
        let data = try keyPair.data()
        try identityKeyStore.store(identityKeyData: data)
        return keyPair.publicKey.data
    }

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
     - returns: The public data of the generated signed pre key for uploading
     - throws: `SignalError`
    */
    public func createSignedPrekey(id: UInt32, timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)) throws -> Data {
        let privateKey = try identityKeyStore.getIdentityKey().privateKey
        let key = try SignalCrypto.generateSignedPreKey(
            identityKey: privateKey,
            id: id, timestamp: timestamp)

        try signedPreKeyStore.store(signedPreKey: key)
        return try key.publicKey.data()
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
     - returns: The public data of the pre keys for uploading
     - throws: `SignalError` errors
    */
    public func createPreKeys(start: UInt32, count: Int) throws -> [Data] {
        let keys = try SignalCrypto.generatePreKeys(start: start, count: count)
        for key in keys {
            try preKeyStore.store(preKey: key)
        }
        return try keys.map { try $0.publicKey.data() }
    }
}
