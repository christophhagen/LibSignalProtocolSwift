//
//  IdentityKeyStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `IdentityKeyStoreDelegate` protocol to handle the Identity Keys of the
 Signal Protocol API. The keys should be stored in a secure database and be treated as
 unspecified data blobs. Register your implementation with an instance of `KeyStore` to
 receive events.
 */
public protocol IdentityKeyStoreDelegate {

    associatedtype Address: Hashable

    /**
     Return the identity key pair. This key should be generated once at
     install time by calling `SignalCrypto.generateIdentityKeyPair()`.
     - note: An appropriate error should be thrown, if no identity key exists
     - returns: The identity key pair data
     - throws: `SignalError` of type `storageError`
     */
    func getIdentityKeyData() throws -> Data

    /**
     Save the identity key pair.
     - parameter identityKeyData: The data to store
     - throws: `SignalError` of type `storageError`, if the data could not be saved
     */
    func store(identityKeyData: Data) throws

    /**
     Return the local registration id. This id should be generated once at
     install time by calling `KeyStore.generateRegistrationID()`.
     - note: An appropriate error should be thrown if no local registration id exists
     - returns: The local registration id
     - throws: `SignalError` of type `storageError`
     */
    func getLocalRegistrationID() throws -> UInt32

    /**
     Determine whether a remote client's identity is trusted. The convention is
     that the TextSecure protocol is 'trust on first use.'  This means that an
     identity key is considered 'trusted' if there is no entry for the recipient in
     the local store, or if it matches the saved key for a recipient in the local store.
     Only if it mismatches an entry in the local store is it considered 'untrusted.'

     - parameter identity: The identity key to verify
     - parameter address: The address of the remote client
     - returns: `true` if trusted, `false` if not trusted
     */
    func isTrusted(identity: Data, for address: Address) -> Bool

    /**
     Store a remote client's identity key as trusted. The value of key_data may be null.
     In this case remove the key data from the identity store, but retain any metadata
     that may be kept alongside it.

     - note: An appropriate error should be thrown if the identity could not be saved
     - parameter identity: The identity key data (may be nil, if the key should be removed)
     - parameter address: The address of the remote client
     - throws: `SignalError` of type `storageError`
     */
    func store(identity: Data?, for address: Address) throws
}

extension IdentityKeyStoreDelegate {

    /**
     Return the identity key pair. This key should be generated once at
     install time by calling `KeyStore.generateIdentityKeyPair()`.
     - note: Possible errors:
     - `storageError` if the key data could not be accessed
     - `invalidProtBuf` if the data is corrupt
     - returns: The identity key pair
     - throws: `SignalError` errors
     */
    func getIdentityKey() throws -> KeyPair {
        let identity = try getIdentityKeyData()
        return try KeyPair(from: identity)
    }

    /**
     Save the identity key pair.
     - note: Possible errors:
     - `invalidProtBuf` if key could not be converted to data
     - `storageError`, if the data could not be saved
     - parameter identityKeyData: The data to store
     - throws: `SignalError` errors
     */
    func store(identityKey: KeyPair) throws {
        try store(identityKeyData: try identityKey.data())
    }

    /**
     Store a remote client's identity key as trusted. The value of key_data may be null.
     In this case remove the key data from the identity store, but retain any metadata
     that may be kept alongside it.

     - note: An appropriate error should be thrown if the identity could not be saved
     - parameter identity: The identity key (may be nil, if the key should be removed)
     - parameter address: The address of the remote client
     - throws: `SignalError` of type `storageError`
     */
    func store(identity: PublicKey?, for address: Address) throws {
        try store(identity: identity?.data, for: address)
    }

    /**
     Determine whether a remote client's identity is trusted. The convention is
     that the TextSecure protocol is 'trust on first use.'  This means that an
     identity key is considered 'trusted' if there is no entry for the recipient in
     the local store, or if it matches the saved key for a recipient in the local store.
     Only if it mismatches an entry in the local store is it considered 'untrusted.'

     - parameter identity: The identity key to verify
     - parameter address: The address of the remote client
     - returns: `true` if trusted, `false` if not trusted
     */
    func isTrusted(identity: PublicKey, for address: Address) -> Bool {
        return isTrusted(identity: identity.data, for: address)
    }
}
