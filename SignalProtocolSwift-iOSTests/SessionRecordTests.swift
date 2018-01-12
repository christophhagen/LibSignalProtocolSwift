//
//  SessionRecordTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 08.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocolSwift

class SessionRecordTests: XCTestCase {
    
    func testSerializeSingleSession() {
        guard let testRatchetKey1 = try? KeyPair().publicKey,
            let testRatchetKey2 = try? KeyPair().publicKey else {
                XCTFail("Could not create keys")
                return
        }
        let state = SessionState()
        guard fillTestSessionState(state: state, ratchetKey1: testRatchetKey1, ratchetKey2: testRatchetKey2) else {
            return
        }
        let record = SessionRecord(state: state)
        guard let recordSerialized = try? record.data() else {
            XCTFail("Could not serialize record")
            return
        }

        guard let newRecord = try? SessionRecord(from: recordSerialized) else {
            XCTFail("Could not deserialize record")
            return
        }
        /* Verify that the initial and deserialized states match */
        guard record == newRecord else {
            XCTFail("Records don't match")
            return
        }
    }

    func testSerializeMultipleSessions() {
        /* Create several test keys */
        guard let testRatchetKey1a = try? KeyPair().publicKey,
            let testRatchetKey1b = try? KeyPair().publicKey,
            let testRatchetKey2a = try? KeyPair().publicKey,
            let testRatchetKey2b = try? KeyPair().publicKey,
            let testRatchetKey3a = try? KeyPair().publicKey,
            let testRatchetKey3b = try? KeyPair().publicKey else {
                XCTFail("Could not create keys")
                return
        }

        /* Create the session record with the first state */
        let state1 = SessionState()
        guard fillTestSessionState(state: state1, ratchetKey1: testRatchetKey1a, ratchetKey2: testRatchetKey1b) else {
            return
        }
        let record = SessionRecord(state: state1)

        /* Archive the current state and fill the new state */
        record.archiveCurrentState()
        let state2 = record.state
        guard fillTestSessionState(state: state2, ratchetKey1: testRatchetKey2a, ratchetKey2: testRatchetKey2b) else {
            return
        }

        /* Archive the current state and fill the new state */
        record.archiveCurrentState()
        let state3 = record.state
        guard fillTestSessionState(state: state3, ratchetKey1: testRatchetKey3a, ratchetKey2: testRatchetKey3b) else {
            return
        }

        guard let recordSerialized = try? record.data() else {
            XCTFail("Could not serialize record")
            return
        }

        guard let newRecord = try? SessionRecord(from: recordSerialized) else {
            XCTFail("Could not deserialize record")
            return
        }

        guard newRecord.previousStates.count == 2 else {
            XCTFail("Invalid number of previous states")
            return
        }

        guard record == newRecord else {
            XCTFail("Records don't match")
            return
        }
    }

    func testSessionReceiverChainCount() {
        let kdf = HKDF(messageVersion: .version2)
        let keySeed = Data(repeating: 0x42, count: 32)

        /* Create 7 instances of receiver chain data */
        var chainKeys = [RatchetChainKey]()
        var ratchetKeys = [PublicKey]()
        for _ in 0..<7 {
            let key = RatchetChainKey(kdf: kdf, key: keySeed, index: 0)
            chainKeys.append(key)
            do {
                try ratchetKeys.append(KeyPair().publicKey)
            } catch {
                XCTFail("Could not create keys")
                return
            }
        }

        /* Create a new session state instance */
        let state = SessionState()

        /* Add 7 instances of receiver chain data */
        for i in 0..<7 {
            let chain = ReceiverChain(ratchetKey: ratchetKeys[i], chainKey: chainKeys[i])
            state.add(receiverChain: chain)
        }

        /* Verify that only the latter 5 are actually there */
        for i in 0..<2 {
            if state.getReceiverChainKey(for: ratchetKeys[i]) != nil {
                XCTFail("Should not have receiver chain")
                return
            }
        }
        for i in 2..<7 {
            guard let key = state.getReceiverChainKey(for: ratchetKeys[i]) else {
                XCTFail("Could not get receiver chain")
                return
            }
            guard key.key == chainKeys[i].key else {
                XCTFail("Keys are not equal")
                return
            }
        }
    }


    private func fillTestSessionState(state: SessionState, ratchetKey1: PublicKey?, ratchetKey2: PublicKey?) -> Bool {

        /* Set the session version */
        state.version = 2

        /* Set local and remote identity keys */
        do {
            state.localIdentity = try KeyPair().publicKey
            state.remoteIdentity = try KeyPair().publicKey
        } catch {
            XCTFail("Could not create keys")
            return false
        }

        /* Set the root key */
        let kdf = HKDF(messageVersion: .version2)
        let keySeed = Data(repeating: 0x42, count: 32)
        state.rootKey = RatchetRootKey(kdf: kdf, key: keySeed)

        /* Set the previous counter */
        state.previousCounter = 4

        /* Set the sender chain */
        do {
            let senderRatchetKeyPair = try KeyPair()
            let ratchetChainkey = RatchetChainKey(kdf: kdf, key: keySeed, index: 0)
            state.senderChain = SenderChain(ratchetKey: senderRatchetKeyPair, chainKey: ratchetChainkey)
        } catch {
            XCTFail("Could not create ratchet key pair")
            return false
        }

        /* Set the receiver chains */
        if let key = ratchetKey1 {
            let chainKey = RatchetChainKey(kdf: kdf, key: keySeed, index: 0)
            let chain = ReceiverChain(ratchetKey: key, chainKey: chainKey)
            state.add(receiverChain: chain)
            do {
                let messageKeys = try chainKey.messageKeys()
                state.set(messageKeys: messageKeys, for: key)
            } catch {
                XCTFail("Could not get message keys for ratchet key 1")
                if let err = error as? SignalError {
                    print(err.longDescription)
                }
                return false
            }
        }

        if let key = ratchetKey2 {
            let chainKey = RatchetChainKey(kdf: kdf, key: keySeed, index: 0)
            let chain = ReceiverChain(ratchetKey: key, chainKey: chainKey)
            state.add(receiverChain: chain)
            do {
                let messageKeys = try chainKey.messageKeys()
                state.set(messageKeys: messageKeys, for: key)
            } catch {
                XCTFail("Could not get message keys for ratchet key 2")
                return false
            }
        }

        /* Set pending pre-key */
        do {
            let baseKey = try KeyPair().publicKey
            state.pendingPreKey = PendingPreKey(preKeyId: 1234, signedPreKeyId: 5678, baseKey: baseKey)
        } catch {
            XCTFail("Could not set pending pre key")
            return false
        }

        state.remoteRegistrationID = 0xDEADBEEF
        state.localRegistrationID = 0xBAADF00D
        state.needsRefresh = false
        guard let aliceBaseKey = try? KeyPair().publicKey else {
            XCTFail("Could not create base key for Alice")
            return false
        }
        state.aliceBaseKey = aliceBaseKey
        return true
    }

}
