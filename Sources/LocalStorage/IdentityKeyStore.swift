//
//  IdentityKeyStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `IdentityKeyStore` protocol to handle the identity keys of the
 Signal Protocol. The keys should be stored in a secure database and be treated as
 unspecified data blobs. 
 */
public protocol IdentityKeyStore: class {

    /// The type that distinguishes different devices/users
    associatedtype Address: Hashable

    /**
     Return the identity key pair. This key should be generated once at
     install time by calling `SignalCrypto.generateIdentityKeyPair()`,
     or given to the constructor.
     - note: An appropriate error should be thrown, if no identity key exists
     - returns: The identity key pair data
     - throws: `SignalError` of type `storageError`
     */
    func getIdentityKeyData() throws -> Data

    /**
     Return the identity for the given address, if there is any.
     - note: An appropriate error should be thrown if the identity could not be accessed
     - parameter address: The address of the remote client
     - returns: The identity for the address, or nil if no data exists
     - throws: `SignalError` of type `storageError`
     */
    func identity(for address: Address) throws -> Data?

    /**
     Store a remote client's identity key as trusted.
     - note: An appropriate error should be thrown if the identity could not be saved
     - parameter identity: The identity key data (may be nil, if the key should be removed)
     - parameter address: The address of the remote client
     - throws: `SignalError` of type `storageError`
     */
    func store(identity: Data?, for address: Address) throws
}

extension IdentityKeyStore {

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
     Return the public identity key. This key should be generated once at
     install time by calling `KeyStore.generateIdentityKeyPair()`.
     - note: Possible errors:
     - `storageError` if the key data could not be accessed
     - `invalidProtBuf` if the data is corrupt
     - returns: The public identity key data
     - throws: `SignalError` errors
     */
    func getPublicIdentityKey() throws -> Data {
        let identity = try getIdentityKeyData()
        let pair = try KeyPair(from: identity)
        return pair.publicKey.data
    }

    /**
     Return the public identity key data.
     - note: Possible errors:
     - `storageError` if the key data could not be accessed
     - `invalidProtBuf` if the data is corrupt
     - returns: The public identity key data
     - throws: `SignalError` errors
     */
    public func getIdentityKeyPublicData() throws -> Data {
        let identity = try getIdentityKeyData()
        let key = try KeyPair(from: identity)
        return key.publicKey.data
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
     - throws: `SignalError` errors
     */
    func isTrusted(identity: Data, for address: Address) throws -> Bool {
        if let data = try self.identity(for: address) {
            return data == identity
        }
        return true
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
    func isTrusted(identity: PublicKey, for address: Address) throws -> Bool {
        return try isTrusted(identity: identity.data, for: address)
    }
}
