//
//  SenderKeyRecordTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 04.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocol

class SenderKeyRecordTests: XCTestCase {

    private func createTestSenderKeyState(id: UInt32, iteration: UInt32) throws -> SenderKeyState {
        let senderKey = try SignalCrypto.generateSenderKey()
        let chainKey = SenderChainKey(iteration: iteration, chainKey: senderKey)
        let signingKey = try SignalCrypto.generateSenderSigningKey()
        return SenderKeyState(
            keyId: id,
            chainKey: chainKey,
            signaturePublicKey: signingKey.publicKey,
            signaturePrivateKey: signingKey.privateKey)
    }

    func testSerializeSenderKeyState() {
        guard let state = try? createTestSenderKeyState(id: 1234, iteration: 1) else {
            XCTFail("Could not create SenderKeyState")
            return
        }
        guard let messageKey = try? state.chainKey.messageKey() else {
            XCTFail("Could not create message key")
            return
        }
        state.add(messageKey: messageKey)

        guard let record = try? state.protoData() else {
            XCTFail("Could not serialize SenderKeyState")
            return
        }

        guard let newState = try? SenderKeyState(from: record) else {
            XCTFail("Could not deserialize SenderKeyState")
            return
        }
        guard newState == state else {
            XCTFail("SenderKeyStates not equal")
            return
        }
        guard let newMessageKey = newState.messageKey(for: 1) else {
            XCTFail("Could not get new message key")
            return
        }
        guard newMessageKey == messageKey else {
            XCTFail("Message keys not equal")
            return
        }
    }

    func testSerializeSenderKeyRecord() {
        let record = SenderKeyRecord()

        guard let serialized = try? record.protoData() else {
            XCTFail("Could not serialize SenderKeyRecord")
            return
        }

        guard let newRecord = try? SenderKeyRecord(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyRecord")
            return
        }
        guard newRecord == record else {
            XCTFail("SenderKeyRecords not equal")
            return
        }
    }

    func testSerializeSenderKeyRecordWithStates() {
        let record = SenderKeyRecord()

        guard let senderKey = try? SignalCrypto.generateSenderKey() else {
            XCTFail("Could not create SenderKey")
            return
        }
        guard let senderSigningKey = try? SignalCrypto.generateSenderSigningKey() else {
            XCTFail("Could not create SenderKey")
            return
        }

        let stateId1: UInt32 = 1000

        record.addState(
            id: stateId1,
            iteration: 1,
            chainKey: senderKey,
            signatureKeyPair: senderSigningKey)

        guard let senderKey2 = try? SignalCrypto.generateSenderKey() else {
            XCTFail("Could not create SenderKey")
            return
        }
        guard let senderSigningKey2 = try? SignalCrypto.generateSenderSigningKey() else {
            XCTFail("Could not create SenderKey")
            return
        }
        let stateId2: UInt32 = 1001
        record.addState(
            id: stateId2,
            iteration: 2,
            chainKey: senderKey2,
            signatureKeyPair: senderSigningKey2)

        guard let state = record.state(for: stateId1) else {
            XCTFail("\(stateId1) missed")
            return
        }
        XCTAssertEqual(state.keyId, stateId1)

        guard let state = record.state(for: stateId2) else {
            XCTFail("\(stateId2) missed")
            return
        }
        XCTAssertEqual(state.keyId, stateId2)
        
        guard let serialized = try? record.protoData() else {
            XCTFail("Could not serialize SenderKeyRecord")
            return
        }

        guard let newRecord = try? SenderKeyRecord(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyRecord")
            return
        }
        // Equal operator also compares states
        guard newRecord == record else {
            XCTFail("SenderKeyRecords not equal")
            return
        }
        guard let state = record.state(for: stateId1),
            let state2 = newRecord.state(for: stateId1), state == state2 else {
                XCTFail("State \(stateId1) not equal")
                return
        }
        guard let state3 = record.state(for: stateId2),
            let state4 = newRecord.state(for: stateId2), state3 == state4 else {
                XCTFail("State \(stateId2) not equal")
                return
        }
    }

    func testSenderKeyRecordTooManyStates() {
        let record = SenderKeyRecord()

        /* Create and set state id=1000, iteration=1 */
        guard let senderKey = try? SignalCrypto.generateSenderKey() else {
            XCTFail("Could not create SenderKey")
            return
        }
        guard let senderSigningKey = try? SignalCrypto.generateSenderSigningKey() else {
            XCTFail("Could not create SenderKey")
            return
        }

        record.addState(
            id: 1000,
            iteration: 1,
            chainKey: senderKey,
            signatureKeyPair: senderSigningKey)

        /* Create and set states id=1001..1010, iteration=2..11 */
        for i in UInt32(0)..<10 {
            /* Create and set state id=1000, iteration=1 */
            guard let senderKey = try? SignalCrypto.generateSenderKey() else {
                XCTFail("Could not create SenderKey")
                return
            }
            guard let senderSigningKey = try? SignalCrypto.generateSenderSigningKey() else {
                XCTFail("Could not create SenderKey")
                return
            }
            record.addState(
                id: 1001 + i,
                iteration: 2 + i,
                chainKey: senderKey,
                signatureKeyPair: senderSigningKey)
        }

        guard let state = record.state else {
            XCTFail("Could not get SenderKeyState")
            return
        }
        guard state.keyId == 1010 else {
            XCTFail("Invalid keyId \(state.keyId) for SenderKeyState")
            return
        }
    }
}
