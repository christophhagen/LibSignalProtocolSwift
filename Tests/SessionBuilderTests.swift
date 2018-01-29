//
//  SessionBuilderTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 05.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocolSwift

class SessionBuilderTests: XCTestCase {

    /**
     This test doesn't make sense for swift, since we can't call `SessionBuilder.process(preKeyBundle:)`
     without a signedPreKey. If we provide any prekey, then the signature verification will fail before
     the missing unsigned pre key is checked.
    */
    func testBasicPreKeyV2() {
        let aliceStore = TestStore()
        let aliceSessionBuilder = SessionBuilder(remoteAddress: bobAddress, store: aliceStore)

        let bobStore = TestStore()

        guard let bobPreKeyPair = try? KeyPair() else {
            XCTFail("Could not create pre key pair")
            return
        }
        guard let bobIdentityKeyPair = try? bobStore.identityKeyStore.getIdentityKey() else {
            XCTFail("Could not get Bob identity key pair")
            return
        }
        let bundle = SessionPreKeyBundle(
            preKeyId: 31337,
            preKeyPublic: bobPreKeyPair.publicKey,
            signedPreKeyId: 0,
            signedPreKeyPublic: bobIdentityKeyPair.publicKey, // Doesn't really make sense for Swift
            signedPreKeySignature: Data(),
            identityKey: bobIdentityKeyPair.publicKey)

        do {
            try aliceSessionBuilder.process(preKeyBundle: bundle)
        } catch {
            return
        }
        XCTFail("Bundle processing should fail")
    }

    func testBasicPreKeyV3() {
        let aliceStore = TestStore()
        let aliceSessionBuilder = SessionBuilder(remoteAddress: bobAddress, store: aliceStore)

        let bobStore = TestStore()
        
        guard let bobPreKeyPair = try? KeyPair(),
            let bobSignedPreKeyPair = try? KeyPair() else {
            XCTFail("Could not create pre key pairs")
            return
        }
        guard let bobIdentityKeyPair = try? bobStore.identityKeyStore.getIdentityKey() else {
            XCTFail("Could not get Bob identity key pair")
            return
        }
        guard let bobSignedPreKeySignature =
            try? bobIdentityKeyPair.privateKey.sign(
                message: bobSignedPreKeyPair.publicKey.data) else {
            XCTFail("Could not create signature")
            return
        }

        let signedPreKeyId: UInt32 = 22

        let bobPreKey = SessionPreKeyBundle(
            preKeyId: 31337,
            preKeyPublic: bobPreKeyPair.publicKey,
            signedPreKeyId: signedPreKeyId,
            signedPreKeyPublic: bobSignedPreKeyPair.publicKey,
            signedPreKeySignature: bobSignedPreKeySignature,
            identityKey: bobIdentityKeyPair.publicKey)

        do {
            try aliceSessionBuilder.process(preKeyBundle: bobPreKey)
        } catch {
            XCTFail("Could not process PreKeyBundle")
            return
        }

        guard aliceStore.sessionStore.containsSession(for: bobAddress),
            let loadedRecord: SessionRecord = try? aliceStore.sessionStore.loadSession(for: bobAddress) else {
            XCTFail("Could not load session")
            return
        }
        guard loadedRecord.state.version == 3 else {
            XCTFail("Invalid version \(loadedRecord.state.version) of session")
            return
        }

        let originalMessage = "L'homme est condamnÈ ‡ Ítre libre".data(using: .utf8)!
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        guard let outgoingMessage = try? aliceSessionCipher.encrypt(originalMessage) else {
            XCTFail("Could not encrypt message")
            return
        }
        guard outgoingMessage.type == .preKey else {
            XCTFail("Invalid type of encrypted message")
            return
        }
        guard let incomingMessage = try? PreKeySignalMessage(from: outgoingMessage.data) else {
            XCTFail("Could not deserialize PreKeySignalMessage")
            return
        }
        let bobPreKeyRecord = SessionPreKey(id: bobPreKey.preKeyId, keyPair: bobPreKeyPair)
        do {
            try bobStore.preKeyStore.store(preKey: bobPreKeyRecord)
        } catch {
            XCTFail("Could not store preKey")
            return
        }

        let bobSignedPreKeyRecord = SessionSignedPreKey(
            id: signedPreKeyId,
            timestamp: UInt64(Date().timeIntervalSince1970),
            keyPair: bobSignedPreKeyPair,
            signature: bobSignedPreKeySignature)

        do {
            try bobStore.signedPreKeyStore.store(signedPreKey: bobSignedPreKeyRecord)
        } catch {
            XCTFail("Could not store SignedPreKey")
            return
        }

        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

        guard let plaintext = try? bobSessionCipher.decrypt(preKeySignalMessage: incomingMessage) else {
            XCTFail("Could not decrypt message")
            return
        }

        guard bobStore.sessionStore.containsSession(for: aliceAddress) else {
            XCTFail("No session created")
            return
        }
        guard let aliceRecipientSessionRecord: SessionRecord = try? bobStore.sessionStore.loadSession(for: aliceAddress) else {
            XCTFail("Could not load session for Alice")
            return
        }
        let aliceRecipientSessionState = aliceRecipientSessionRecord.state
        guard aliceRecipientSessionState.version == 3,
            aliceRecipientSessionState.aliceBaseKey != nil else {
                XCTFail("Session Version mismatch or base key missing")
                return
        }
        guard plaintext == originalMessage else {
            XCTFail("Decrypted message doesn't match original")
            return
        }

        guard let bobOutgoingMessage = try? bobSessionCipher.encrypt(originalMessage) else {
            XCTFail("Could not encrypt message for Alice")
            return
        }
        guard bobOutgoingMessage.type == .signal else {
            XCTFail("Invalid message type")
            return
        }

        guard let aliceSignalMessage = try? SignalMessage(from: bobOutgoingMessage.data),
            let alicePlaintext = try? aliceSessionCipher.decrypt(signalMessage: aliceSignalMessage),
            alicePlaintext == originalMessage else {
                XCTFail("Could not decrypt message for Alice")
                return
        }
        /* Pre-interaction tests complete */
        runInteraction(aliceStore: aliceStore, bobStore: bobStore)

        /* Create Alice's new session data */
        let newAliceStore = TestStore()
        let newAliceSessionBuilder = SessionBuilder(remoteAddress: bobAddress, store: newAliceStore)
        let newAliceSessionCipher = SessionCipher(store: newAliceStore, remoteAddress: bobAddress)

        /* Create Bob's new pre key bundle */
        guard let newBobPreKeyPair = try? KeyPair(),
            let newBobSignedPreKeyPair = try? KeyPair() else {
                XCTFail("Could not create key pairs")
            return
        }

        guard let newBobIdentityKeyPair = try? bobStore.identityKeyStore.getIdentityKey() else {
            XCTFail("Could not get Bob identity key pair")
            return
        }
        guard let newBobSignedPreKeySignature =
            try? newBobIdentityKeyPair.privateKey.sign(
                message: newBobSignedPreKeyPair.publicKey.data) else {
                    XCTFail("Could not create signature")
                    return
        }

        let newSignedPreKeyId: UInt32 = 23

        let newBobPreKey = SessionPreKeyBundle(
            preKeyId: 31338,
            preKeyPublic: newBobPreKeyPair.publicKey,
            signedPreKeyId: newSignedPreKeyId,
            signedPreKeyPublic: newBobSignedPreKeyPair.publicKey,
            signedPreKeySignature: newBobSignedPreKeySignature,
            identityKey: newBobIdentityKeyPair.publicKey)

        /* Save the new pre key and signed pre key in Bob's data store */
        let newBobPreKeyRecord = SessionPreKey(id: newBobPreKey.preKeyId, keyPair: newBobPreKeyPair)
        do {
            try bobStore.preKeyStore.store(preKey: newBobPreKeyRecord)
        } catch {
            XCTFail("Could not store new preKey")
            return
        }

        let newBobSignedPreKeyRecord = SessionSignedPreKey(
            id: newSignedPreKeyId,
            timestamp: UInt64(Date().timeIntervalSince1970),
            keyPair: newBobSignedPreKeyPair,
            signature: newBobSignedPreKeySignature)

        do {
            try bobStore.signedPreKeyStore.store(signedPreKey: newBobSignedPreKeyRecord)
        } catch {
            XCTFail("Could not store new SignedPreKey")
            return
        }

        /* Have Alice process Bob's pre key bundle */
        do {
            try newAliceSessionBuilder.process(preKeyBundle: newBobPreKey)
        } catch {
            XCTFail("Could not process new PreKeyBundle")
            return
        }

        /* Have Alice encrypt a message for Bob */
        guard let newOutgoingMessage = try? newAliceSessionCipher.encrypt(originalMessage) else {
            XCTFail("Could not encrypt message for Bob")
            return
        }
        guard newOutgoingMessage.type == .preKey else {
            XCTFail("Invalid message type")
            return
        }

        /* Have Bob try to decrypt the message */
        guard let alicePreKeySignalMessage = try? PreKeySignalMessage(from: newOutgoingMessage.data) else {
            XCTFail("Not a valid PreKeySignalMessage")
            return
        }
        do {
            let _ = try bobSessionCipher.decrypt(preKeySignalMessage: alicePreKeySignalMessage)
            XCTFail("Could decrypt the message even though the identity should be untrusted")
            return
        } catch let error as SignalError where error.type == .untrustedIdentity {

        } catch {
            XCTFail("Failed trying to decrypt message from Alice")
            return
        }

        /* Save the identity key to Bob's store */
        do {
            try bobStore.identityKeyStore.store(identity: alicePreKeySignalMessage.identityKey, for: aliceAddress)
        } catch {
            XCTFail("Could not store identity key")
            return
        }

        /* Try the decrypt again, this time it should succeed */
        guard let newPlaintext = try? bobSessionCipher.decrypt(preKeySignalMessage: alicePreKeySignalMessage),
        newPlaintext == originalMessage else {
            XCTFail("Could not decrypt message after identity change")
            return
        }

        /* Create a new pre key for Bob */
        guard let testPublicKey = try? KeyPair().publicKey,
            let aliceIdentityKeyPair = try? KeyPair() else {
                XCTFail("Could not create key")
                return
        }

        let bundle = SessionPreKeyBundle(
            preKeyId: 31337,
            preKeyPublic: testPublicKey,
            signedPreKeyId: 23,
            signedPreKeyPublic: newBobSignedPreKeyPair.publicKey,
            signedPreKeySignature: newBobSignedPreKeySignature,
            identityKey: aliceIdentityKeyPair.publicKey)

        do {
            let _ = try newAliceSessionBuilder.process(preKeyBundle: bundle)
            XCTFail("Processing bundle should fail")
        } catch let error as SignalError where error.type == .untrustedIdentity {

        } catch {
            XCTFail("Failed to process bundle, but not with the right error")
            return
        }
    }

    func testBadSignedPreKeySignature() {
        /* Create Alice's data store and session builder */
        let aliceStore = TestStore()
        let aliceSessionBuilder = SessionBuilder(remoteAddress: bobAddress, store: aliceStore)

        /* Create Bob's data store */
        let bobStore = TestStore()

        /* Create Bob's regular and signed pre key pairs */
        guard let bobPreKeyPair = try? KeyPair(),
            let bobSignedPreKeyPair = try? KeyPair(),
            let bobIdentityKeyPair = try? bobStore.identityKeyStore.getIdentityKey() else {
            XCTFail("Could not generate pre key pair and signed pre key pair for bob")
            return
        }

        /* Create Bob's signed pre key signature */
        guard let bobSignedPreKeySignature =
            try? bobStore.identityKeyStore.getIdentityKey().privateKey.sign(message: bobSignedPreKeyPair.publicKey.data) else {
                XCTFail("Could not sign signed pre key")
                return
        }

        for i in 0..<bobSignedPreKeySignature.count {
            var modifiedSignature = bobSignedPreKeySignature

            /* Intentionally corrupt the signature data */
            modifiedSignature[i / 8] ^= 0x01 << (i % 8)

            /* Create a pre key bundle */
            let bundle = SessionPreKeyBundle(
                preKeyId: 31337,
                preKeyPublic: bobPreKeyPair.publicKey,
                signedPreKeyId: 22,
                signedPreKeyPublic: bobSignedPreKeyPair.publicKey,
                signedPreKeySignature: modifiedSignature,
                identityKey: bobIdentityKeyPair.publicKey)

            /* Process the bundle and make sure we fail with an invalid signature error */
            // Note: libsignal-protocol-c fails with invalid key error here
            do {
                try aliceSessionBuilder.process(preKeyBundle: bundle)
                XCTFail("Processing bundle should fail")
            } catch let error as SignalError where error.type == .invalidSignature {

            } catch {
                XCTFail("Failed to process bundle, but not with the right error")
                return
            }
        }

        /* Create a correct pre key bundle */
        let bundle = SessionPreKeyBundle(
            preKeyId: 31337,
            preKeyPublic: bobPreKeyPair.publicKey,
            signedPreKeyId: 22,
            signedPreKeyPublic: bobSignedPreKeyPair.publicKey,
            signedPreKeySignature: bobSignedPreKeySignature,
            identityKey: bobIdentityKeyPair.publicKey)

        /* Process the bundle and make sure we do not fail */
        do {
            try aliceSessionBuilder.process(preKeyBundle: bundle)
        } catch {
            XCTFail("Failed to process bundle")
            return
        }
    }

    func testRepeatBundleMessageV2() {
        /* This test doesn't make sense in SignalProtocolSwift, since
         a pre key bundle can't be created without a signed pre key.
         */
    }

    func testRepeatBundleMessageV3() {
        /* Create Alice's data store and session builder */
        let aliceStore = TestStore()
        let aliceSessionBuilder = SessionBuilder(remoteAddress: bobAddress, store: aliceStore)

        /* Create Bob's data store */
        let bobStore = TestStore()

        /* Create Bob's regular and signed pre key pairs */
        guard let bobPreKeyPair = try? KeyPair(),
            let bobSignedPreKeyPair = try? KeyPair(),
            let bobIdentityKeyPair = try? bobStore.identityKeyStore.getIdentityKey() else {
                XCTFail("Could not generate pre key pair and signed pre key pair for bob")
                return
        }

        /* Create Bob's signed pre key signature */
        guard let bobSignedPreKeySignature =
            try? bobStore.identityKeyStore.getIdentityKey().privateKey.sign(message: bobSignedPreKeyPair.publicKey.data) else {
                XCTFail("Could not sign signed pre key")
                return
        }

        /* Create a pre key bundle */
        let bobPreKey = SessionPreKeyBundle(
            preKeyId: 31337,
            preKeyPublic: bobPreKeyPair.publicKey,
            signedPreKeyId: 22,
            signedPreKeyPublic: bobSignedPreKeyPair.publicKey,
            signedPreKeySignature: bobSignedPreKeySignature,
            identityKey: bobIdentityKeyPair.publicKey)

        /* Add Bob's pre keys to Bob's data store */
        do {
            let preKey = SessionPreKey(id: bobPreKey.preKeyId, keyPair: bobPreKeyPair)
            try bobStore.preKeyStore.store(preKey: preKey)
            let signedPreKey = SessionSignedPreKey(
                id: bobPreKey.signedPreKeyId,
                timestamp: UInt64(Date().timeIntervalSince1970),
                keyPair: bobSignedPreKeyPair,
                signature: bobSignedPreKeySignature)
            try bobStore.signedPreKeyStore.store(signedPreKey: signedPreKey)
        } catch {
            XCTFail("Could not store pre key or signed pre key")
            return
        }

        /* Have Alice process Bob's pre key bundle */
        do {
            try aliceSessionBuilder.process(preKeyBundle: bobPreKey)
        } catch {
            XCTFail("Could not process pre key bundle")
            return
        }

        /* Initialize Alice's session cipher */
        let originalMessage = "L'homme est condamnÈ ‡ Ítre libre".data(using: .utf8)!
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)

        guard let outgoingMessage1 = try? aliceSessionCipher.encrypt(originalMessage),
            let outgoingMessage2 = try? aliceSessionCipher.encrypt(originalMessage) else {
                XCTFail("Could not encrypt messages")
                return
        }

        guard outgoingMessage1.type == .preKey, outgoingMessage2.type == .preKey else {
            XCTFail("Invalid message type(s)")
            return
        }

        /* Copy to an incoming message */
        guard let incomingMessage = try? PreKeySignalMessage(from: outgoingMessage1.data) else {
            XCTFail("Could not create incoming PreKeySignalMessage")
            return
        }

        /* Create Bob's session cipher */
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

        /* Have Bob decrypt the message, and verify that it matches */
        guard let plaintext1 = try? bobSessionCipher.decrypt(preKeySignalMessage: incomingMessage),
            plaintext1 == originalMessage else {
                XCTFail("Could not (correctly) decrypt PreKeySignalMessage")
                return
        }

        /* Construct an outgoing message from Bob back to Alice */
        guard let bobOutgoingMessage = try? bobSessionCipher.encrypt(originalMessage) else {
            XCTFail("Could not encrypt message from Bob")
            return
        }

        /* Have Alice decrypt the message, and verify that it matches */
        do {
            let message = try SignalMessage(from: bobOutgoingMessage.data)
            let decrypted = try aliceSessionCipher.decrypt(signalMessage: message)
            guard decrypted == originalMessage else {
                throw SignalError(.invalidMessage, "")
            }
        } catch {
            XCTFail("Could not (correctly) decrypt message from Bob")
            return
        }

        /* The Test */
        do {
            let incomingMessage2 = try PreKeySignalMessage(from: outgoingMessage2.data)
            let plaintext = try bobSessionCipher.decrypt(preKeySignalMessage: incomingMessage2)
            guard plaintext == originalMessage else {
                throw SignalError(.invalidMessage, "")
            }
        } catch {
            XCTFail("Could not decrypt second PreKeySignalMessage")
            return
        }

        do {
            let bobOutgoingMessage2 = try bobSessionCipher.encrypt(originalMessage)
            let incomingMessage2 = try SignalMessage(from: bobOutgoingMessage2.data)
            let decrypted = try aliceSessionCipher.decrypt(signalMessage: incomingMessage2)
            guard decrypted == originalMessage else {
                throw SignalError(.invalidMessage, "")
            }
        } catch {
            XCTFail("Could not encrypt or decrypt second SignalMessage")
            return
        }
    }

    func testBadMessageBundle() {
        /* Create Alice's data store and session builder */
        let aliceStore = TestStore()
        let aliceSessionBuilder = SessionBuilder(remoteAddress: bobAddress, store: aliceStore)

        /* Create Bob's data store */
        let bobStore = TestStore()
        
        /* Create Bob's regular and signed pre key pairs */
        guard let bobPreKeyPair = try? KeyPair(),
            let bobSignedPreKeyPair = try? KeyPair(),
            let bobIdentityKeyPair = try? bobStore.identityKeyStore.getIdentityKey() else {
                XCTFail("Could not generate pre key pair and signed pre key pair for bob")
                return
        }

        /* Create Bob's signed pre key signature */
        guard let bobSignedPreKeySignature =
            try? bobStore.identityKeyStore.getIdentityKey().privateKey.sign(message: bobSignedPreKeyPair.publicKey.data) else {
                XCTFail("Could not sign signed pre key")
                return
        }

        /* Create a pre key bundle */
        let bobPreKey = SessionPreKeyBundle(
            preKeyId: 31337,
            preKeyPublic: bobPreKeyPair.publicKey,
            signedPreKeyId: 22,
            signedPreKeyPublic: bobSignedPreKeyPair.publicKey,
            signedPreKeySignature: bobSignedPreKeySignature,
            identityKey: bobIdentityKeyPair.publicKey)

        /* Add Bob's pre keys to Bob's data store */
        do {
            let preKey = SessionPreKey(id: bobPreKey.preKeyId, keyPair: bobPreKeyPair)
            try bobStore.preKeyStore.store(preKey: preKey)
            let signedPreKey = SessionSignedPreKey(
                id: bobPreKey.signedPreKeyId,
                timestamp: UInt64(Date().timeIntervalSince1970),
                keyPair: bobSignedPreKeyPair,
                signature: bobSignedPreKeySignature)
            try bobStore.signedPreKeyStore.store(signedPreKey: signedPreKey)
        } catch {
            XCTFail("Could not store pre key or signed pre key")
            return
        }

        /* Have Alice process Bob's pre key bundle */
        do {
            try aliceSessionBuilder.process(preKeyBundle: bobPreKey)
        } catch {
            XCTFail("Could not process pre key bundle")
            return
        }

        /* Initialize Alice's session cipher */
        let originalMessage = "L'homme est condamnÈ ‡ Ítre libre".data(using: .utf8)!
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)

        guard let outgoingMessage1 = try? aliceSessionCipher.encrypt(originalMessage) else {
                XCTFail("Could not encrypt messages")
                return
        }

        guard outgoingMessage1.type == .preKey else {
            XCTFail("Invalid message type(s)")
            return
        }

        let goodMessage = outgoingMessage1.data
        var badMessage = goodMessage
        badMessage[badMessage.count - 10] ^= 0x01

        guard let badIncomingMessage = try? PreKeySignalMessage(from: badMessage) else {
            XCTFail("Could not create PreKeySignalMessage from bas message")
            return
        }
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

        /* Check that the decrypt fails with an invalid message error */
        do {
            let _ = try bobSessionCipher.decrypt(preKeySignalMessage: badIncomingMessage)
            XCTFail("Should not decrypt bad message")
            return
        } catch let error as SignalError where error.type == .invalidMessage {

        } catch {
            XCTFail("Invalid error for decyption of bad message")
            return
        }

        /* Make sure the pre key is there */
        guard bobStore.preKeyStore.containsPreKey(for: 31337) else {
            XCTFail("Bob has no pre key")
            return
        }

        /* Check that the decrypt succeeds with the good message */
        do {
            let goodIncomingMessage = try PreKeySignalMessage(from: goodMessage)
            let decrypted = try bobSessionCipher.decrypt(preKeySignalMessage: goodIncomingMessage)
            guard decrypted == originalMessage else {
                XCTFail("Decrypted message invalid")
                return
            }
        } catch {
            XCTFail("Could not decrypt good message")
            return
        }

        /* Make sure the pre key is no longer there */
        guard bobStore.preKeyStore.containsPreKey(for: 31337) == false else {
            XCTFail("Bob still has the pre key")
            return
        }
    }

    func testOptionalOneTimePreKey() {
        /* Create Alice's data store and session builder */
        let aliceStore = TestStore()
        let aliceSessionBuilder = SessionBuilder(remoteAddress: bobAddress, store: aliceStore)

        /* Create Bob's data store */
        let bobStore = TestStore()
        
        /* Create Bob's regular and signed pre key pairs */
        guard let bobPreKeyPair = try? KeyPair(),
            let bobSignedPreKeyPair = try? KeyPair(),
            let bobIdentityKeyPair = try? bobStore.identityKeyStore.getIdentityKey() else {
                XCTFail("Could not generate pre key pair and signed pre key pair for bob")
                return
        }

        /* Create Bob's signed pre key signature */
        guard let bobSignedPreKeySignature =
            try? bobStore.identityKeyStore.getIdentityKey().privateKey.sign(message: bobSignedPreKeyPair.publicKey.data) else {
                XCTFail("Could not sign signed pre key")
                return
        }

        /* Create a pre key bundle */
        let bobPreKey = SessionPreKeyBundle(
            preKeyId: 0,
            preKeyPublic: nil,
            signedPreKeyId: 22,
            signedPreKeyPublic: bobSignedPreKeyPair.publicKey,
            signedPreKeySignature: bobSignedPreKeySignature,
            identityKey: bobIdentityKeyPair.publicKey)

        /* Have Alice process Bob's pre key bundle */
        do {
            try aliceSessionBuilder.process(preKeyBundle: bobPreKey)
        } catch {
            XCTFail("Could not process pre key bundle")
            return
        }

        /* Find and verify the session version in Alice's store */
        guard aliceStore.sessionStore.containsSession(for: bobAddress),
            let record: SessionRecord = try? aliceStore.sessionStore.loadSession(for: bobAddress),
            record.state.version == 3 else {
                XCTFail("Alice has no valid session (version)")
                return
        }

        /* Initialize Alice's session cipher */
        let originalMessage = "L'homme est condamnÈ ‡ Ítre libre".data(using: .utf8)!
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)

        guard let outgoingMessage = try? aliceSessionCipher.encrypt(originalMessage) else {
            XCTFail("Could not encrypt messages")
            return
        }

        XCTAssert(outgoingMessage.type == .preKey, "Invalid message type(s)")

        /* Convert to an incoming message */
        guard let incomingMessage = try? PreKeySignalMessage(from: outgoingMessage.data) else {
            XCTFail("Could not create PreKeySignalMessage")
            return
        }
        /* Make sure the pre key ID is not present */
        XCTAssertNil(incomingMessage.preKeyId, "PreKeySignalMessage has pre key id")

        /* Add Bob's pre keys to Bob's data store */
        do {
            let preKey = SessionPreKey(id: bobPreKey.preKeyId, keyPair: bobPreKeyPair)
            try bobStore.preKeyStore.store(preKey: preKey)
            let signedPreKey = SessionSignedPreKey(
                id: bobPreKey.signedPreKeyId,
                timestamp: UInt64(Date().timeIntervalSince1970),
                keyPair: bobSignedPreKeyPair,
                signature: bobSignedPreKeySignature)
            try bobStore.signedPreKeyStore.store(signedPreKey: signedPreKey)
        } catch {
            XCTFail("Could not store pre key or signed pre key")
            return
        }

        /* Create Bob's session cipher */
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

        guard let plaintext = try? bobSessionCipher.decrypt(preKeySignalMessage: incomingMessage) else {
            XCTFail("Could not decrypt PreKeySignalMessage")
            return
        }

        guard bobStore.sessionStore.containsSession(for: aliceAddress),
            let record1: SessionRecord = try? bobStore.sessionStore.loadSession(for: aliceAddress),
            record1.state.version == 3,
            record1.state.aliceBaseKey != nil else {
                XCTFail("Bob has no or invalid session for Alice")
                return
        }
        XCTAssert(plaintext == originalMessage, "Decrypted message invalid")
    }

    private func createLoopingMessage(index: Int) -> Data {
        var data = "You can only desire based on what you know:  ".data(using: .utf8)!
        data[data.count-1] = UInt8(index)
        return data
    }
    private func createLoopingMessageShort(index: Int) -> Data {
        var data = "What do we mean by saying that existence precedes essence? We mean that man first of all exists, encounters himself, surges up in the world--and defines himself aftward.  ".data(using: .utf8)!
        data[data.count-1] = UInt8(index)
        return data
    }

    private func runInteraction(aliceStore: TestStore, bobStore: TestStore) {

        /* Create the session ciphers */
        let aliceSessionCipher = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
        let bobSessionCipher = SessionCipher(store: bobStore, remoteAddress: aliceAddress)

        /* Create a test message */
        let originalMessage = "smert ze smert".data(using: .utf8)!

        /* Simulate Alice sending a message to Bob */
        do {
            let aliceMessage = try aliceSessionCipher.encrypt(originalMessage)
            if aliceMessage.type != .signal { throw SignalError(.invalidMessage, "") }
            let signalMessage = try SignalMessage(from: aliceMessage.data)
            let plaintext = try bobSessionCipher.decrypt(signalMessage: signalMessage)
            if plaintext != originalMessage { throw SignalError(.invalidMessage, "") }
        } catch {
            XCTFail("Could not encrypt or decrypt message to Bob")
            return
        }

        /* Simulate Bob sending a message to Alice */
        do {
            let bobMessage = try bobSessionCipher.encrypt(originalMessage)
            if bobMessage.type != .signal { throw SignalError(.invalidMessage, "") }
            let signalMessage = try SignalMessage(from: bobMessage.data)
            let plaintext = try aliceSessionCipher.decrypt(signalMessage: signalMessage)
            if plaintext != originalMessage { throw SignalError(.invalidMessage, "") }
        } catch {
            XCTFail("Could not encrypt or decrypt message to Alice")
            return
        }

        /* Looping Alice -> Bob */
        for i in 0..<10 {
            let loopingMessage = createLoopingMessage(index: i)
            do {
                let aliceLoopingMessage = try aliceSessionCipher.encrypt(loopingMessage)
                let aliceMessage = try SignalMessage(from: aliceLoopingMessage.data)
                let plaintext = try bobSessionCipher.decrypt(signalMessage: aliceMessage)
                if plaintext != loopingMessage { throw SignalError(.invalidMessage, "") }
            } catch {
                XCTFail("Could not encrypt or decrypt message to Bob")
                return
            }
        }

        /* Looping Bob -> Alice */
        for i in 0..<10 {
            let loopingMessage = createLoopingMessage(index: i)
            do {
                let bobLoopingMessage = try bobSessionCipher.encrypt(loopingMessage)
                let bobMessage = try SignalMessage(from: bobLoopingMessage.data)
                let plaintext = try aliceSessionCipher.decrypt(signalMessage: bobMessage)
                if plaintext != loopingMessage { throw SignalError(.invalidMessage, "") }
            } catch {
                XCTFail("Could not encrypt or decrypt message to Alice")
                return
            }
        }

        /* Generate a shuffled list of encrypted messages for later use */
        var messages = [(Data, Data)]()
        for i in 0..<10 {
            let plaintext = createLoopingMessage(index: i)
            guard let ciphertext = try? aliceSessionCipher.encrypt(plaintext) else {
                XCTFail("Could not encrypt message for Bob")
                return
            }
            messages.append((plaintext,ciphertext.data))
        }
        shuffle(&messages)

        /* Looping Alice -> Bob (repeated) */
        do {
            try sendLoopingMessage(from: aliceSessionCipher, to: bobSessionCipher)
        } catch {
            XCTFail("Could not encrypt/decrypt message for Bob")
            return
        }

        /* Looping Bob -> Alice (repeated) */
        do {
            try sendLoopingMessage(from: bobSessionCipher, to: aliceSessionCipher)
        } catch {
            XCTFail("Could not encrypt/decrypt message for Alice")
            return
        }

        /* Shuffled Alice -> Bob */
        for i in 0..<10 {
            do {
                let message = try SignalMessage(from: messages[i].1)
                let plaintext = try bobSessionCipher.decrypt(signalMessage: message)
                if plaintext != messages[i].0 { throw SignalError(.invalidMessage, "") }
            } catch {
                XCTFail("Could not decrypt shuffled message for Bob")
                return
            }
        }
    }

    private func sendLoopingMessage(from sender: SessionCipher<TestStore>, to receiver: SessionCipher<TestStore>) throws {
        for i in 0..<10 {
            let loopingMessage = createLoopingMessage(index: i)
            let ciphertext = try sender.encrypt(loopingMessage)
            let message = try SignalMessage(from: ciphertext.data)
            let plaintext = try receiver.decrypt(signalMessage: message)
            if plaintext != loopingMessage { throw SignalError(.invalidMessage, "") }
        }
    }
}
