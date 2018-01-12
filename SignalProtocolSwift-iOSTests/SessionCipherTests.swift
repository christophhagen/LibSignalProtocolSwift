//
//  SessionCipherTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 06.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocolSwift

private let aliceAddress = SignalAddress(identifier: "+14159999999", deviceId: 1)
private let bobAddress = SignalAddress(identifier: "+14158888888", deviceId: 1)


class SessionCipherTests: XCTestCase {

    func testBasicSessionV3() {
        /* Create Alice's session record */
        let aliceSessionRecord = SessionRecord(state: nil)

        /* Create Bob's session record */
        let bobSessionRecord = SessionRecord(state: nil)

        initializeSessionsV3(aliceSessionRecord.state, bobSessionRecord.state)
        runInteraction(aliceSessionRecord, bobSessionRecord)

    }

    private func initializeSessionsV3(_ aliceState: SessionState, _ bobstate: SessionState) {
        /* Generate Alice's identity key */
        /* Generate Alice's base key */
        /* Generate Alice's ephemeral key */
        /* Generate Bob's identity key */
        /* Generate Bob's base key */
        /* Generate Bob's pre-key */
        guard let aliceIdentityKey = try? KeyPair(),
            let aliceBaseKey = try? KeyPair(),
            let bobIdentityKey = try? KeyPair(),
            let bobBaseKey = try? KeyPair() else {
                XCTFail("Could not generate keys")
                return
        }

        do {
            try aliceState.aliceInitialize(
                ourIdentityKey: aliceIdentityKey,
                ourBaseKey: aliceBaseKey,
                theirIdentityKey: bobIdentityKey.publicKey,
                theirSignedPreKey: bobBaseKey.publicKey,
                theirOneTimePreKey: nil,
                theirRatchetKey: bobBaseKey.publicKey)

            try bobstate.bobInitialize(
                ourIdentityKey: bobIdentityKey,
                ourSignedPreKey: bobBaseKey,
                ourOneTimePreKey: nil,
                ourRatchetKey: bobBaseKey,
                theirIdentityKey: aliceIdentityKey.publicKey,
                theirBaseKey: aliceBaseKey.publicKey)

        } catch {
            XCTFail("Could not initialize sessions")
            return
        }
    }

    private func runInteraction(_ aliceRecord: SessionRecord, _ bobRecord: SessionRecord) {

        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()

        /* Store the two sessions in their data stores */
        do {
            try aliceStore.sessionStore.store(session: aliceRecord, for: bobAddress)
            try bobStore.sessionStore.store(session: bobRecord, for: aliceAddress)
        } catch {
            XCTFail("Could not store sessions")
            return
        }

        /* Create two session cipher instances */
        let aliceCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

         /* Encrypt a test message from Alice */
        let alicePlaintext = "This is a plaintext message.".data(using: .utf8)!
        guard let aliceMessage = try? aliceCipher.encrypt(paddedMessage: alicePlaintext) else {
            XCTFail("Could not encrypt message from Alice")
            return
        }

        /* Have Bob decrypt the test message */
        do {
            try decryptAndCompareMessages(
                cipher: bobCipher,
                ciphertext: aliceMessage.data,
                plaintext: alicePlaintext)
        } catch {
            XCTFail("Could not decrypt message from Alice")
            return
        }

        /* Encrypt a reply from Bob */
        let bobReply = "This is a message from Bob.".data(using: .utf8)!
        guard let replyMessage = try? bobCipher.encrypt(paddedMessage: bobReply) else {
            XCTFail("Could not encrypt reply from Bob")
            return
        }

        /* Have Alice decrypt the reply message */
        do {
            try decryptAndCompareMessages(
                cipher: aliceCipher,
                ciphertext: replyMessage.data,
                plaintext: bobReply)
        } catch {
            XCTFail("Could not decrypt reply message from Bob")
            return
        }

        /* Generate 50 indexed Alice test messages */
        guard let aliceMessages = try? generateTestMessageCollections(cipher: aliceCipher, size: 50) else {
            XCTFail("Could not generate TestMessageCollection from Alice")
            return
        }

        /* Iterate through half the collection and try to decrypt messages */
        for i in 0..<25 {
            do {
                try decryptAndCompareMessages(
                    cipher: bobCipher,
                    ciphertext: aliceMessages[i].1,
                    plaintext: aliceMessages[i].0)
            } catch {
                XCTFail("Could not decrypt message collection")
                return
            }
        }

        /* Generate 50 indexed Bob test messages */
        guard let bobMessages = try? generateTestMessageCollections(cipher: bobCipher, size: 50) else {
            XCTFail("Could not generate TestMessageCollection from Bob")
            return
        }

        do {
            /* Iterate through half the collection and try to decrypt messages */
            for i in 0..<25 {
                try decryptAndCompareMessages(cipher: aliceCipher, ciphertext: bobMessages[i].1, plaintext: bobMessages[i].0)
            }
            /* Iterate through the second half of the collection and try to decrypt messages */
            for i in 25..<50 {
                try decryptAndCompareMessages(cipher: bobCipher, ciphertext: aliceMessages[i].1, plaintext: aliceMessages[i].0)
            }
            /* Iterate through the second half of the collection and try to decrypt messages */
            for i in 25..<50 {
                try decryptAndCompareMessages(cipher: aliceCipher, ciphertext: bobMessages[i].1, plaintext: bobMessages[i].0)
            }
        } catch {
            XCTFail("Could not decrypt all messages")
            return
        }

    }

    func testMessageKeyLimits() {
        /* Create Alice's session record */
        let aliceSessionRecord = SessionRecord(state: nil)

        /* Create Bob's session record */
        let bobSessionRecord = SessionRecord(state: nil)

        /* Initialize the sessions */
        initializeSessionsV3(aliceSessionRecord.state, bobSessionRecord.state)

        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()

        /* Store the two sessions in their data stores */
        do {
            try aliceStore.sessionStore.store(session: aliceSessionRecord, for: bobAddress)
            try bobStore.sessionStore.store(session: bobSessionRecord, for: aliceAddress)
        } catch {
            XCTFail("Could not store sessions")
            return
        }

        /* Create two session cipher instances */
        let aliceCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

        /* Encrypt enough messages to go past our limit */
        let alicePlaintext = "you've never been so hungry, you've never been so cold".data(using: .utf8)!
        var inflight = [SignalMessage]()
        for i in 0..<2010 {
            do {
                let aliceMessage = try aliceCipher.encrypt(paddedMessage: alicePlaintext)
                if aliceMessage.type != .signal { throw SignalError(.invalidMessage, "") }
                let message = try SignalMessage(from: aliceMessage.data)
                inflight.append(message)
            } catch {
                XCTFail("Could not encrypt message \(i)")
                return
            }
        }

        do {
            /* Try decrypting in-flight message 1001 */
            let message1001 = try bobCipher.decrypt(signalMessage: inflight[1000])
            if message1001 != alicePlaintext { throw SignalError(.invalidMessage, "") }
            /* Try decrypting in-flight message 2010 */
            let message2010 = try bobCipher.decrypt(signalMessage: inflight[2009])
            if message2010 != alicePlaintext { throw SignalError(.invalidMessage, "") }

        } catch {
            XCTFail("Could not decrypt message")
        }

        /* Try decrypting in-flight message 0, which should fail */
        do {
            let _ = try bobCipher.decrypt(signalMessage: inflight[0])
            XCTFail("Should not decrypt message")
            return
        } catch let error as SignalError where error.type == .duplicateMessage {

        } catch {
            XCTFail("Decryption failed with invalid error")
            return
        }
    }

    private func generateTestMessageCollections(cipher: SessionCipher<TestStore>, size: Int) throws -> [(Data, Data)] {
        /*
         * This test message is kept here as a byte array constant, rather than
         * a string literal, since it contains characters not valid in ASCII.
         * A null placeholder is located at the end, which is replaced with an
         * index value when generated derived test messages.
         */
        let testMessage = Data(
            [0xD1, 0x81, 0xD0, 0xBC, 0xD0, 0xB5, 0xD1, 0x80,
             0xD1, 0x82, 0xD1, 0x8C, 0x20, 0xD0, 0xB7, 0xD0,
             0xB0, 0x20, 0xD1, 0x81, 0xD0, 0xBC, 0xD0, 0xB5,
             0xD1, 0x80, 0xD1, 0x82, 0xD1, 0x8C, 0x20, 0x00])

        var messages = [(Data, Data)]()
        for i in 0..<size {
            /* Generate the plaintext */
            var plaintext = testMessage
            plaintext[testMessage.count-1] = UInt8(i)

            /* Generate the ciphertext */
            let encryptedMessage = try cipher.encrypt(paddedMessage: plaintext)

            /* Add the generated messages to the arrays */
            messages.append((plaintext,encryptedMessage.data))
        }

        /* Randomize the two arrays */
        shuffle(&messages)
        return messages
    }

    private func decryptAndCompareMessages(cipher: SessionCipher<TestStore>, ciphertext: Data, plaintext: Data) throws {
        /* Create a signal_message from the ciphertext */
        let message = try SignalMessage(from: ciphertext)

        /* Decrypt the message */
        let decrypted = try cipher.decrypt(signalMessage: message)

        /* Compare the messages */
        if plaintext != decrypted {
            throw SignalError(.invalidMessage, "")
        }
    }
}
