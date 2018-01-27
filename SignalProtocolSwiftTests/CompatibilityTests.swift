//
//  CompatibilityTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
import Curve25519
@testable import SignalProtocolSwift


private let ratchetKey = Data([
    0x05, 0x1c, 0xb7, 0x59, 0x66, 0xf2, 0xe9, 0x3a, 0x36, 0x91, 0xd5,
    0xfa, 0x94, 0x2c, 0xb2, 0x15, 0x66, 0xa1, 0xc0, 0x8b, 0x8d, 0x73,
    0xca, 0x3f, 0x4d, 0x6d, 0xf8, 0xb8, 0xbf, 0xa2, 0xe4, 0xee, 0x28])

private let baseKeyPublic = Data([
    0x05, 0x1c, 0xb7, 0x59, 0x66, 0xf2, 0xe9, 0x3a, 0x36, 0x91, 0xd5,
    0xfa, 0x94, 0x2c, 0xb2, 0x15, 0x66, 0xa1, 0xc0, 0x8b, 0x8d, 0x73,
    0x34, 0x3a, 0xe5, 0x6d, 0xd0, 0xc3, 0x49, 0x77, 0xe4, 0xee, 0x28])

private let signaturePublic = Data(
    [0x05, 0x1b, 0xb7, 0x59, 0x66, 0xf2, 0xe9, 0x3a, 0x36, 0x91, 0xdf,
     0xff, 0x94, 0x2b, 0xb2, 0xa4, 0x66, 0xa1, 0xc0, 0x8b, 0x8d, 0x78,
     0xca, 0x3f, 0x4d, 0x6d, 0xf8, 0xb8, 0xbf, 0xa2, 0xe4, 0xee, 0x28])

private let serializedSignalMessage = Data(
    [51,10,33,5,28,183,89,102,242,233,58,54,145,213,250,148,44,178,21,102,161,
     192,139,141,115,202,63,77,109,248,184,191,162,228,238,40,16,3,24,2,34,15,
     1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,191,53,108,65,168,67,34,241])

private let serializedPreKeySignalMessage = Data(
    [51,8,169,18,18,33,5,28,183,89,102,242,233,58,54,145,213,250,148,44,178,21,102,161,
     192,139,141,115,52,58,229,109,208,195,73,119,228,238,40,26,33,5,27,183,89,102,242,
     233,58,54,145,223,255,148,43,178,164,102,161,192,139,141,120,202,63,77,109,248,184,
     191,162,228,238,40,34,65,51,10,33,5,28,183,89,102,242,233,58,54,145,213,250,148,44,
     178,21,102,161,192,139,141,115,202,63,77,109,248,184,191,162,228,238,40,16,3,24,2,34,
     15,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,191,53,108,65,168,67,34,241,40,123,48,128,27])

private let serializedSenderKeyDistributionMessage = Data(
    [51,8,1,16,210,9,26,8,9,8,7,6,5,4,3,2,34,33,5,27,183,89,102,242,233,58,54,145,223,255,
     148,43,178,164,102,161,192,139,141,120,202,63,77,109,248,184,191,162,228,238,40])

private let ciphertext = Data([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])

private let macKey = Data([9,8,7,6,5,4,3,2])

class CompatibilityTests: XCTestCase {

    /**
     Check if a SignalMessage can correctly be serialized
    */
    func testSerializeSignalMessage() {

        guard let (alice, bob) = try? createBobAndAlice(),
            let senderRatchetKey = try? PublicKey(point: ratchetKey) else {
            XCTFail("Could not create keys")
            return
        }

        guard let message = try? SignalMessage(
            messageVersion: 3,
            macKey: macKey, senderRatchetKey: senderRatchetKey,
            counter: 3, previousCounter: 2,
            cipherText: ciphertext,
            senderIdentityKey: alice.publicKey,
            receiverIdentityKey: bob.publicKey) else {
                XCTFail("Could not create message")
                return
        }

        guard let record = try? message.baseMessage().data else {
            XCTFail("Could not serialize message")
            return
        }

        guard record.count == serializedSignalMessage.count else {
            XCTFail("Record length invalid: \(record.count) != \(serializedSignalMessage.count)")
            return
        }

        guard let recovered = try? SignalMessage(from: record) else {
            XCTFail("Could not deserialize SignalMessage")
            return
        }

        guard (try? recovered.verifyMac(
            senderIdentityKey: alice.publicKey,
            receiverIdentityKey: bob.publicKey,
            macKey: macKey)) ?? false else {
                XCTFail("Invalid signature")
                return
        }

        guard recovered.counter == message.counter,
            recovered.previousCounter == message.previousCounter,
            record == serializedSignalMessage else {
            XCTFail("Records not equal")
            return
        }
    }

    /**
     Check if a SenderKeyMessage can correctly be serialized
     */
    func testSerializeSenderKeyMessage() {

        guard let (alice, _) = try? createBobAndAlice() else {
                XCTFail("Could not create keys")
                return
        }

        guard let message = try? SenderKeyMessage(
            keyId: 1, iteration: 17,
            cipherText: ciphertext,
            signatureKey: alice.privateKey) else {
                XCTFail("Could not create SenderKeyMessage")
                return
        }

        guard let serialized = try? message.baseMessage().data else {
            XCTFail("Could not serialize SenderKeyMessage")
            return
        }

        // 7 byte overhead
        let count = Curve25519.signatureLength + ciphertext.count + 7
        guard serialized.count == count else {
            XCTFail("Invalid length \(serialized.count) != \(count)")
            return
        }

        // Not checking for exact equality since signature will be different

        guard let rebuilt = try? SenderKeyMessage(from: serialized) else {
            XCTFail("Could not create SenderKeyMessage from data")
            return
        }

        guard ((try? rebuilt.verify(signatureKey: alice.publicKey)) ?? false) else {
            XCTFail("Invalid signature")
            return
        }

        guard rebuilt.keyId == message.keyId,
            rebuilt.iteration == message.iteration,
            rebuilt.cipherText == message.cipherText else {
            XCTFail("Properties not equal")
            return
        }
    }

    /**
     Check if a PreKeySignalMessage can correctly be serialized
     */
    func testSerializePreKeySignalMessage() {

        guard let (alice, bob) = try? createBobAndAlice() else {
                XCTFail("Could not create keys")
                return
        }
        let senderRatchetKey = try! PublicKey(point: ratchetKey)
        let baseKey = try! PublicKey(point: baseKeyPublic)

        let message = try! SignalMessage(messageVersion: 3,
                                         macKey: macKey,
                                         senderRatchetKey: senderRatchetKey,
                                         counter: 3, previousCounter: 2,
                                         cipherText: ciphertext,
                                         senderIdentityKey: alice.publicKey, receiverIdentityKey: bob.publicKey)

        let preKeyMessage = PreKeySignalMessage(
            messageVersion: 3, registrationId: 123, preKeyId: 2345, signedPreKeyId: 3456,
            baseKey: baseKey, identityKey: alice.publicKey, message: message)

        guard let record = try? preKeyMessage.baseMessage().data else {
            XCTFail("Could not serialize message")
            return
        }

        guard record.count == serializedPreKeySignalMessage.count else {
            XCTFail("Invalid length \(record.count) (\(serializedPreKeySignalMessage.count))")
            return
        }

        guard record == serializedPreKeySignalMessage else {
            XCTFail("Invalid record")
            return
        }

    }

    /**
     Check if a SenderKeyDistributionMessage can correctly be serialized
     */
    func testSerializeSenderKeyDistributionMessage() {

        let chainKey = Data([9,8,7,6,5,4,3,2])

        let signatureKey = try! PublicKey(point: signaturePublic)

        let message = SenderKeyDistributionMessage(
            id: 1, iteration: 1234, chainKey: chainKey, signatureKey: signatureKey)

        guard let record = try? message.baseMessage().data else {
            XCTFail("Could not serialize message")
            return
        }

        guard record.count == serializedSenderKeyDistributionMessage.count else {
            XCTFail("Invalid length \(record.count) != (\(serializedSenderKeyDistributionMessage.count))")
            return
        }

        guard record == serializedSenderKeyDistributionMessage else {
            XCTFail("Invalid record")
            return
        }
    }
}
