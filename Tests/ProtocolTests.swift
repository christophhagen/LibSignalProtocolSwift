//
//  ProtocolTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 02.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocol

private let ciphertext = "WhisperCipherText".data(using: .utf8)!

class ProtocolTests: XCTestCase {

    func testSerializeSignalMessage() {

        let senderRatchetKey = try! KeyPair().publicKey
        let senderIdentityKey = try! KeyPair().publicKey
        let receiverIdentityKey = try! KeyPair().publicKey

        let macKey = Data(count: RatchetMessageKeys.macKeyLength)

        guard let message = try? SignalMessage(
            messageVersion: 3,
            macKey: macKey,
            senderRatchetKey: senderRatchetKey,
            counter: 2,
            previousCounter: 1,
            cipherText: ciphertext,
            senderIdentityKey: senderIdentityKey,
            receiverIdentityKey: receiverIdentityKey) else {
                XCTFail("Could not create SignalMessage")
                return
        }

        guard let serialized = try? message.baseMessage().data else {
            XCTFail("Could not serialize SignalMessage")
            return
        }

        guard let newMessage = try? SignalMessage(from: serialized) else {
                XCTFail("Could not deserialize SignalMessage")
                return
        }

        guard (try? newMessage.verifyMac(
            senderIdentityKey: senderIdentityKey,
            receiverIdentityKey: receiverIdentityKey,
            macKey: macKey)) ?? false else {
                XCTFail("Invalid signature")
                return
        }

        guard newMessage == message else {
            XCTFail("Messages not equal")
            return
        }
    }

    func testSerializePreKeySignalMessage() {

        guard let senderRatchetKey = try? KeyPair().publicKey,
            let senderIdentityKey = try? KeyPair().publicKey,
            let receiverIdentityKey = try? KeyPair().publicKey,
            let baseKey = try? KeyPair().publicKey,
            let identityKey = try? KeyPair().publicKey else {
                XCTFail("Could not create keys")
                return
        }

        let macKey = Data(count: RatchetMessageKeys.macKeyLength)

        guard let message = try? SignalMessage(
            messageVersion: 3,
            macKey: macKey,
            senderRatchetKey: senderRatchetKey,
            counter: 2,
            previousCounter: 1,
            cipherText: ciphertext,
            senderIdentityKey: senderIdentityKey,
            receiverIdentityKey: receiverIdentityKey) else {
                XCTFail("Could not create SignalMessage")
                return
        }

        let preKeyId: UInt32 = 56

        let preKeyMessage = PreKeySignalMessage(
            messageVersion: 3,
            preKeyId: preKeyId,
            signedPreKeyId: 72,
            baseKey: baseKey,
            identityKey: identityKey,
            message: message)

        guard let serialized = try? preKeyMessage.baseMessage().data else {
            XCTFail("Could not serialize PreKeySignalMessage")
            return
        }

        guard let newMessage = try? PreKeySignalMessage(from: serialized) else {
            XCTFail("Could not deserialize PreKeySignalMessage")
            return
        }

        guard newMessage.version == preKeyMessage.version,
            newMessage.identityKey == preKeyMessage.identityKey,
            newMessage.preKeyId == preKeyMessage.preKeyId,
            newMessage.signedPreKeyId == preKeyMessage.signedPreKeyId,
            newMessage.baseKey == preKeyMessage.baseKey,
            newMessage.message == preKeyMessage.message else {
                XCTFail("Messages not equal")
                return
        }
    }

    func testSerializeSenderKeyMessage() {


        guard let signatureKeyPair = try? KeyPair() else {
            XCTFail("Could not create keys")
            return
        }

        guard let message = try? SenderKeyMessage(
            keyId: 10,
            iteration: 1,
            cipherText: Data(ciphertext),
            signatureKey: signatureKeyPair.privateKey) else {
                XCTFail("Could not create SenderKeyMessage")
                return
        }

        guard (try? message.verify(signatureKey: signatureKeyPair.publicKey)) ?? false else {
            XCTFail("Invalid signature for SenderKeyMessage")
            return
        }

        guard let serialized = try? message.baseMessage().data else {
            XCTFail("Could not serialize SenderKeyMessage")
            return
        }

        guard let newMessage = try? SenderKeyMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyMessage")
            return
        }

        guard (try? newMessage.verify(signatureKey: signatureKeyPair.publicKey)) ?? false else {
            XCTFail("Invalid signature for SenderKeyMessage")
            return
        }

        guard message.keyId == newMessage.keyId,
            message.iteration == newMessage.iteration,
            message.cipherText == newMessage.cipherText,
            message.messageVersion == newMessage.messageVersion else {
                XCTFail("SenderKeyMessages not equal")
                return
        }
    }

    func testSerializeSenderKeyDistributionMessage() {
        guard let signatureKey = try? KeyPair().publicKey else {
            XCTFail("Could not create keys")
            return
        }
        let chainKey = "WhisperChainKey".data(using: .utf8)!
        let message = SenderKeyDistributionMessage(
            id: 10, iteration: 1,
            chainKey: chainKey, signatureKey: signatureKey)

        guard let serialized = try? message.data() else {
            XCTFail("Could not serialized message")
            return
        }

        guard let deserialized = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialized message")
            return
        }

        guard deserialized == message else {
            XCTFail("Messages are not equal")
            return
        }

    }
}
