//
//  TestStore.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 05.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import SignalProtocolSwift

class TestStore: SignalProtocolStoreContext {

    var identityKeyStore: IdentityKeyStoreDelegate

    var preKeyStore: PreKeyStoreDelegate

    var senderKeyStore: SenderKeyStoreDelegate

    var sessionStore: SessionStoreDelegate

    var signedPreKeyStore: SignedPreKeyStoreDelegate

    init() {
        self.identityKeyStore = TestIdentityStore()
        self.preKeyStore = TestPreKeyStore()
        self.senderKeyStore = TestSenderKeyStore()
        self.sessionStore = TestSessionStore()
        self.signedPreKeyStore = TestSignedPreKeyStore()
    }

    func setIdentity(_ identity: KeyPair) {
        identityKeyStore.identityKey = identity
    }
}

class TestIdentityStore: IdentityKeyStoreDelegate {
    var identityKey: KeyPair?

    var localRegistrationID: UInt32?

    private var identities = [SignalAddress : Data]()

    func isTrusted(identity: Data, for address: SignalAddress) -> Bool {
        guard let id = identities[address] else {
            // Trust if no identity exists for address
            return true
        }
        return id == identity
    }

    func save(identity: Data?, for address: SignalAddress) -> Bool {
        identities[address] = identity
        return true
    }

    init() {
        self.identityKey = try? SignalCrypto.generateIdentityKeyPair()
        self.localRegistrationID = try? SignalCrypto.generateRegistrationId(extendedRange: false)
    }
}

class TestPreKeyStore: PreKeyStoreDelegate {

    private var preKeys = [UInt32 : Data]()

    func preKey(for id: UInt32) -> Data? {
        return preKeys[id]
    }

    func store(preKey: Data, for id: UInt32) -> Bool {
        preKeys[id] = preKey
        return preKeys[id] != nil
    }

    func containsPreKey(for id: UInt32) -> Bool {
        return preKeys[id] != nil
    }

    func removePreKey(for id: UInt32) -> Bool {
        preKeys[id] = nil
        return preKeys[id] == nil
    }
}

class TestSenderKeyStore: SenderKeyStoreDelegate {

    private var senderKeys = [SignalSenderKeyName : Data]()
    
    func loadSenderKey(senderKeyName: SignalSenderKeyName) -> Data? {
        return senderKeys[senderKeyName]
    }

    func store(senderKey: Data, for senderKeyName: SignalSenderKeyName) -> Bool {
        senderKeys[senderKeyName] = senderKey
        return senderKeys[senderKeyName] != nil
    }
}

class TestSessionStore: SessionStoreDelegate {

    private var sessions = [SignalAddress : Data]()

    func loadSession(for address: SignalAddress) -> Data? {
        return sessions[address]
    }

    func subDeviceSessions(for recipientID: String) -> [Int32] {
        return sessions.keys.filter { $0.name == recipientID }.map { $0.deviceId }
    }

    func store(session: Data, for address: SignalAddress) -> Bool {
        sessions[address] = session
        return sessions[address] != nil
    }

    func containsSession(for address: SignalAddress) -> Bool {
        return sessions[address] != nil
    }

    func deleteSession(for address: SignalAddress) -> Bool {
        sessions[address] = nil
        return sessions[address] == nil
    }

    func deleteAllSessions(for recipientID: String) -> Int {
        var count = 0
        for key in sessions.keys.filter({ $0.name == recipientID }) {
            sessions[key] = nil
            count += 1
        }
        return count
    }
}

class TestSignedPreKeyStore: SignedPreKeyStoreDelegate {

    private var signedKeys = [UInt32 : Data]()

    func signedPreKey(for id: UInt32) -> Data? {
        return signedKeys[id]
    }

    func store(signedPreKey: Data, for id: UInt32) -> Bool {
        signedKeys[id] = signedPreKey
        return signedKeys[id] != nil
    }

    func containsSignedPreKey(for id: UInt32) -> Bool {
        return signedKeys[id] != nil
    }

    func removeSignedPreKey(for id: UInt32) -> Bool {
        signedKeys[id] = nil
        return signedKeys[id] == nil
    }


}
