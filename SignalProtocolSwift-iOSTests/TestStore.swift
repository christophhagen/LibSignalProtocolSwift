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

    typealias Address = SignalAddress

    typealias GroupAddress = SignalSenderKeyName

    typealias IdentityKeyStore = TestIdentityStore

    typealias SenderKeyStore = TestSenderKeyStore

    typealias SessionStore = TestSessionStore

    var identityKeyStore: TestIdentityStore

    var preKeyStore: PreKeyStoreDelegate

    var signedPreKeyStore: SignedPreKeyStoreDelegate

    var senderKeyStore: TestSenderKeyStore

    var sessionStore: TestSessionStore

    init() {
        self.identityKeyStore = TestIdentityStore()
        self.preKeyStore = TestPreKeyStore()
        self.senderKeyStore = TestSenderKeyStore()
        self.sessionStore = TestSessionStore()
        self.signedPreKeyStore = TestSignedPreKeyStore()
    }
}

class TestIdentityStore: IdentityKeyStoreDelegate {

    typealias Address = SignalAddress

    private var identityKey: KeyPair!

    private var localRegistrationID: UInt32!

    private var identities = [SignalAddress : Data]()

    func getIdentityKey() throws -> KeyPair {
        if identityKey == nil {
            identityKey = try SignalCrypto.generateIdentityKeyPair()
        }
        return identityKey
    }

    func getLocalRegistrationID() throws -> UInt32 {
        if localRegistrationID == nil {
            localRegistrationID = try SignalCrypto.generateRegistrationId(extendedRange: false)
        }
        return localRegistrationID
    }

    func isTrusted(identity: Data, for address: SignalAddress) -> Bool {
        guard let id = identities[address] else {
            // Trust if no identity exists for address
            return true
        }
        return id == identity
    }

    func store(identity: Data?, for address: SignalAddress) throws {
        identities[address] = identity
    }

    init() {
    }
}

class TestPreKeyStore: PreKeyStoreDelegate {

    typealias Address = SignalAddress

    var lastId: UInt32 = 0

    private var preKeys = [UInt32 : Data]()

    func preKey(for id: UInt32) throws -> Data {
        guard let key = preKeys[id] else {
            throw SignalError(.storageError, "No pre key for id \(id)")
        }
        return key
    }

    func store(preKey: Data, for id: UInt32) throws {
        preKeys[id] = preKey
        lastId = id
    }

    func containsPreKey(for id: UInt32) -> Bool {
        return preKeys[id] != nil
    }

    func removePreKey(for id: UInt32) throws {
        preKeys[id] = nil
    }

}

class TestSenderKeyStore: SenderKeyStoreDelegate {

    typealias Address = SignalSenderKeyName

    private var senderKeys = [SignalSenderKeyName : Data]()
    
    func senderKey(for address: SignalSenderKeyName) -> Data? {
        return senderKeys[address]
    }

    func store(senderKey: Data, for address: SignalSenderKeyName) throws {
        senderKeys[address] = senderKey
    }
}

class TestSessionStore: SessionStoreDelegate {

    typealias Address = SignalAddress

    private var sessions = [Address : Data]()

    func loadSession(for address: Address) -> Data? {
        return sessions[address]
    }

    func subDeviceSessions(for recipientID: String) -> [UInt32] {
        return sessions.keys.filter { $0.identifier == recipientID }.map { $0.deviceId }
    }

    func store(session: Data, for address: Address) throws {
        sessions[address] = session
    }

    func containsSession(for address: Address) -> Bool {
        return sessions[address] != nil
    }

    func deleteSession(for address: Address) throws {
        sessions[address] = nil
    }

    func deleteAllSessions(for recipientID: String) -> Int {
        var count = 0
        for key in sessions.keys.filter({ $0.identifier == recipientID }) {
            sessions[key] = nil
            count += 1
        }
        return count
    }
}

class TestSignedPreKeyStore: SignedPreKeyStoreDelegate {

    private var signedKeys = [UInt32 : Data]()

    var lastId: UInt32 = 0

    func signedPreKey(for id: UInt32) throws -> Data {
        guard let key = signedKeys[id] else {
            throw SignalError(.invalidId, "No signed pre key for id \(id)")
        }
        return key
    }

    func store(signedPreKey: Data, for id: UInt32) throws {
        signedKeys[id] = signedPreKey
        lastId = id
    }

    func containsSignedPreKey(for id: UInt32) -> Bool {
        return signedKeys[id] != nil
    }

    func removeSignedPreKey(for id: UInt32) throws {
        signedKeys[id] = nil
    }

    func allIds() -> [UInt32] {
        return [UInt32](signedKeys.keys)
    }

}
