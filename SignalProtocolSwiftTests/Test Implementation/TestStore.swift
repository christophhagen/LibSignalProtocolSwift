//
//  TestStore.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 05.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import SignalProtocolSwift

/**
 Implement the key store for testing purposes.
 */
class TestStore: KeyStore {

    // MARK: Typealiases

    /// The identifier to distinguish between different devices/users
    typealias Address = SignalAddress

    /// The identifier to distinguish between different groups and devices/users
    typealias GroupAddress = SignalSenderKeyName

    /// The type implementing the identity key store
    typealias IdentityKeyStore = TestIdentityStore

    /// The type implementing the sender key store
    typealias SenderKeyStore = TestSenderKeyStore

    /// The type implementing the session store
    typealias SessionStore = TestSessionStore

    // MARK: Variables

    /// The store for the identity keys
    let identityKeyStore = TestIdentityStore()

    /// The store for the pre keys
    let preKeyStore: PreKeyStore = TestPreKeyStore()

    /// The store for the signed pre keys
    let signedPreKeyStore: SignedPreKeyStore = TestSignedPreKeyStore()

    /// The store for the sender keys
    let senderKeyStore = TestSenderKeyStore()

    /// The store for the sessions
    let sessionStore = TestSessionStore()
}

