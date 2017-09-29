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
protocol IdentityKeyStoreDelegate {

    /**
     Return the identity key pair. This key should be generated once at
     install time by calling `KeyStore.generateIdentityKeyPair()`.
     */
    var identityKey : IdentityKeyPair? { get }

    /**
     Return the local registration id. This id should be generated once at
     install time by calling `KeyStore.generateRegistrationID()`.
     */
    var localRegistrationID: Int { get }

    /**
     Determine whether a remote client's identity is trusted. Th convention is that the TextSecure protocol is 'trust on first use.'  This means that an identity key is considered 'trusted' if there is no entry for the recipient in the local store, or if it matches the saved key for a recipient in the local store. Only if it mismatches an entry in the local store is it considered 'untrusted.'

     - parameter address: The address of the remote client
     - parameter record: The identity key to verify (can be nil)
     - returns: `true` if trusted, `false` if not trusted
     */
    func isTrustedIdentity(for address: CHAddress, and record: [UInt8]?) -> Bool

    /**
     Store a remote client's identity key as trusted. The value of key_data may be null. In this case remove the key data from the identity store, but retain any metadata that may be kept alongside it.

     - parameter address: The address of the remote client
     - parameter record: The identity key (may be null)
     - returns: `true` on success
     */
    func saveIdentity(for address: CHAddress, and record: [UInt8]?) -> Bool

    /**
     Function called to perform cleanup when the data store context is being destroyed.
     */
    func cleanup()
}
