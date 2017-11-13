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

    /**
     Return the identity key pair. This key should be generated once at
     install time by calling `KeyStore.generateIdentityKeyPair()`.
     */
    var identityKey : KeyPair? { get set }

    /**
     Return the local registration id. This id should be generated once at
     install time by calling `KeyStore.generateRegistrationID()`.
     */
    var localRegistrationID: UInt32? { get set }

    /**
     Determine whether a remote client's identity is trusted. The convention is
     that the TextSecure protocol is 'trust on first use.'  This means that an
     identity key is considered 'trusted' if there is no entry for the recipient in
     the local store, or if it matches the saved key for a recipient in the local store.
     Only if it mismatches an entry in the local store is it considered 'untrusted.'

     - parameter identity: The identity key to verify (can be nil)
     - parameter address: The address of the remote client
     - returns: `true` if trusted, `false` if not trusted
     */
    func isTrusted(identity: Data, for address: SignalAddress) -> Bool

    /**
     Store a remote client's identity key as trusted. The value of key_data may be null.
     In this case remove the key data from the identity store, but retain any metadata
     that may be kept alongside it.

     - parameter identity: The identity key (may be null)
     - parameter address: The address of the remote client
     - returns: `true` on success
     */
    func save(identity: Data?, for address: SignalAddress) -> Bool
}
