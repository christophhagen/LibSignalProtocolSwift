//
//  TestStore.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 05.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import SignalProtocolSwift

class TestStore: SignalProtocolStoreContext {

    typealias Address = SignalAddress

    typealias GroupAddress = SignalSenderKeyName

    typealias IdentityKeyStore = TestIdentityStore

    typealias SenderKeyStore = TestSenderKeyStore

    typealias SessionStore = TestSessionStore

    typealias CryptoProvider = SignalCommonCrypto

    let identityKeyStore = TestIdentityStore()

    let preKeyStore: PreKeyStoreDelegate = TestPreKeyStore()

    let signedPreKeyStore: SignedPreKeyStoreDelegate = TestSignedPreKeyStore()

    let senderKeyStore = TestSenderKeyStore()

    let sessionStore = TestSessionStore()

    let cryptoProvider = SignalCommonCrypto()
}

