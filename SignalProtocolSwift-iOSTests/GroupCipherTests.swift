//
//  GroupCipherTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 09.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocolSwift

private let groupSender = SignalSenderKeyName(
    groupId: "nihilist history reading group",
    sender: SignalAddress(name: "+14150001111", deviceId: 1))

class GroupCipherTests: XCTestCase {
    
    func testNoSession() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the session builder */
        let aliceSessionBuilder = GroupSessionBuilder(store: aliceStore)
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(store: aliceStore, senderKeyId: groupSender)
        let bobGroupCipher = GroupCipher(store: bobStore, senderKeyId: groupSender)
        
        /* Create the sender key distribution messages */
        guard let sentAliceDistributionMessage =
            try? aliceSessionBuilder.createSession(senderKeyName: groupSender) else {
                XCTFail("Could not create distribution message")
                return
        }
        guard let serialized = try? sentAliceDistributionMessage.data() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let _ = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Intentionally omitting Bob's processing of received_alice_distribution_message */
        
        /* Encrypt a test message from Alice */
        let alicePlaintext = "smert ze smert".asByteArray
        guard let message = try? aliceGroupCipher.encrypt(paddedPlaintext: alicePlaintext) else {
            XCTFail("could not encrypt message")
            return
        }
        
        /* Attempt to have Bob decrypt the message */
        do {
            let senderKeyMessage = try SenderKeyMessage(from: message.data)
            let _ = try bobGroupCipher.decrypt(ciphertext: senderKeyMessage)
            XCTFail("Did not fail to decrypt message")
        } catch let error as SignalError where error == .noSession {
            
        } catch {
            XCTFail("Did not fail to decrypt message with correct error")
            return
        }
    }
    
    func testBasicEncryptDecrypt() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the session builders */
        let aliceSessionBuilder = GroupSessionBuilder(store: aliceStore)
        let bobSessionBuilder = GroupSessionBuilder(store: bobStore)
        
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(store: aliceStore, senderKeyId: groupSender)
        let bobGroupCipher = GroupCipher(store: bobStore, senderKeyId: groupSender)
        
        /* Create the sender key distribution messages */
        guard let sentAliceDistributionMessage =
            try? aliceSessionBuilder.createSession(senderKeyName: groupSender) else {
                XCTFail("Could not create distribution message")
                return
        }
        guard let serialized = try? sentAliceDistributionMessage.data() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let receivedDistributionMessage = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Processing Alice's distribution message */
        do {
            try bobSessionBuilder.processSession(
                senderKeyName: groupSender,
                distributionMessage: receivedDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }
        
        /* Encrypt a test message from Alice */
        let alicePlaintext = "smert ze smert".asByteArray
        guard let encrypted = try? aliceGroupCipher.encrypt(paddedPlaintext: alicePlaintext) else {
            XCTFail("could not encrypt message")
            return
        }
        
        /* Attempt to have Bob decrypt the message */
        do {
            let senderKeyMessage = try SenderKeyMessage(from: encrypted.data)
            let decrypted = try bobGroupCipher.decrypt(ciphertext: senderKeyMessage)
            guard decrypted == alicePlaintext else {
                XCTFail("Invalid decrypted plaintext")
                return
            }
        } catch {
            XCTFail("Failed to decrypt message")
            return
        }
    }
    
    func testBasicRatchet() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the session builders */
        let aliceSessionBuilder = GroupSessionBuilder(store: aliceStore)
        let bobSessionBuilder = GroupSessionBuilder(store: bobStore)
        
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(store: aliceStore, senderKeyId: groupSender)
        let bobGroupCipher = GroupCipher(store: bobStore, senderKeyId: groupSender)
        
        /* Create the sender key distribution messages */
        guard let sentAliceDistributionMessage =
            try? aliceSessionBuilder.createSession(senderKeyName: groupSender) else {
                XCTFail("Could not create distribution message")
                return
        }
        guard let serialized = try? sentAliceDistributionMessage.data() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let receivedDistributionMessage = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Processing Alice's distribution message */
        do {
            try bobSessionBuilder.processSession(
                senderKeyName: groupSender,
                distributionMessage: receivedDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }
        
        /* Prepare some text to encrypt */
        let alicePlaintext = "smert ze smert".asByteArray
        let alicePlaintext2 = "smert ze smert2".asByteArray
        let alicePlaintext3 = "smert ze smert3".asByteArray
        
        /* Encrypt a series of messages from Alice */
        guard let ciphertext1 = try? aliceGroupCipher.encrypt(paddedPlaintext: alicePlaintext),
            let ciphertext2 = try? aliceGroupCipher.encrypt(paddedPlaintext: alicePlaintext2),
            let ciphertext3 = try? aliceGroupCipher.encrypt(paddedPlaintext: alicePlaintext3) else {
                XCTFail("could not encrypt messages")
                return
        }
        
        do {
            /* Have Bob decrypt the message */
            let message1 = try SenderKeyMessage(from: ciphertext1.data)
            let message2 = try SenderKeyMessage(from: ciphertext2.data)
            let message3 = try SenderKeyMessage(from: ciphertext3.data)
            let plaintext = try bobGroupCipher.decrypt(ciphertext: message1)
            /* Have Bob attempt to decrypt the same message again */
            do {
                let _ = try bobGroupCipher.decrypt(ciphertext: message1)
                XCTFail("Should not decrypt message again")
                return
            } catch let error as SignalError where error == .duplicateMessage {
                
            }
            /* Have Bob decrypt the remaining messages */
            let plaintext2 = try bobGroupCipher.decrypt(ciphertext: message2)
            let plaintext3 = try bobGroupCipher.decrypt(ciphertext: message3)
            guard plaintext == alicePlaintext,
                plaintext2 == alicePlaintext2,
                plaintext3 == alicePlaintext3 else {
                    XCTFail("Messages not correct")
                    return
            }
        } catch {
            XCTFail("Could not decrypt messages")
            return
        }
    }
    
    func testLateJoin() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the session builders */
        let aliceSessionBuilder = GroupSessionBuilder(store: aliceStore)
        
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(store: aliceStore, senderKeyId: groupSender)
        
        /* Create the sender key distribution messages */
        guard let _ =
            try? aliceSessionBuilder.createSession(senderKeyName: groupSender) else {
                XCTFail("Could not create distribution message")
                return
        }
        
        /* Pretend this was sent to some people other than Bob */
        for i in 0..<100 {
            let alicePlaintext = "up the punks up the punks up the punks".asByteArray
            guard let _ = try? aliceGroupCipher.encrypt(paddedPlaintext: alicePlaintext) else {
                XCTFail("Could not encrypt message \(i)")
                return
            }
        }
        
        
        /* Now Bob Joins */
        let bobSessionBuilder = GroupSessionBuilder(store: bobStore)
        let bobGroupCipher = GroupCipher(store: bobStore, senderKeyId: groupSender)
        
        /* Create Alice's sender key distribution message for Bob */
        guard let sentAliceDistributionMessage =
            try? aliceSessionBuilder.createSession(senderKeyName: groupSender) else {
                XCTFail("Could not create distribution message")
                return
        }

        guard let serialized = try? sentAliceDistributionMessage.data() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let receivedDistributionMessage = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Have Bob process Alice's distribution message */
        do {
            try bobSessionBuilder.processSession(
                senderKeyName: groupSender,
                distributionMessage: receivedDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }
        
        /* Alice sends a message welcoming Bob */
        do {
            let plaintext = "welcome to the group".asByteArray
            let ciphertext = try aliceGroupCipher.encrypt(paddedPlaintext: plaintext)
            let message = try SenderKeyMessage(from: ciphertext.data)
            /* Bob decrypts the message */
            let decrypted = try bobGroupCipher.decrypt(ciphertext: message)
            guard decrypted == plaintext else {
                XCTFail("welcome message not correct")
                return
            }
        } catch {
            XCTFail("Could not encrypt or decrypt welcome message")
            return
        }
    }

    private func createWorkingSession() -> (GroupCipher, GroupCipher)? {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the session builders */
        let aliceSessionBuilder = GroupSessionBuilder(store: aliceStore)
        let bobSessionBuilder = GroupSessionBuilder(store: bobStore)

        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(store: aliceStore, senderKeyId: groupSender)
        let bobGroupCipher = GroupCipher(store: bobStore, senderKeyId: groupSender)

        /* Create Alice's sender key distribution message */
        guard let aliceDistributionMessage =
            try? aliceSessionBuilder.createSession(senderKeyName: groupSender) else {
                XCTFail("Could not create distribution message")
                return nil
        }

        /* Have Bob process the distribution message */
        do {
            try bobSessionBuilder.processSession(
                senderKeyName: groupSender,
                distributionMessage: aliceDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return nil
        }
        return (aliceGroupCipher, bobGroupCipher)
    }
    
    func testOutOfOrder() {
        guard let (aliceCipher, bobCipher) = createWorkingSession() else {
            return
        }
        /* Populate a batch of 100 messages */
        let plaintext = "up the punks".asByteArray
        var ciphertexts = [Data]()
        for _ in 0..<100 {
            guard let message = try? aliceCipher.encrypt(paddedPlaintext: plaintext) else {
                XCTFail("Could not encrypt message")
                return
            }
            ciphertexts.append(message.data)
        }
        /* Try decrypting those messages in random order */
        shuffle(&ciphertexts)
        for i in 0..<100 {
            do {
                /* Deserialize the message */
                let deserialized = try SenderKeyMessage(from: ciphertexts[i])
                /* Decrypt the message */
                let decrypted = try bobCipher.decrypt(ciphertext: deserialized)
                guard decrypted == plaintext else {
                    XCTFail("Plaintext doesn't match")
                    return
                }
            } catch {
                XCTFail("Could not decrypt message")
                return
            }
        }
    }

    func testEncryptNoSession() {
        let aliceSenderName = SignalSenderKeyName(
            groupId: "coolio groupio", sender: SignalAddress(name: "+10002223333", deviceId: 1))

        /* Create the test data store for Alice */
        let aliceStore = TestStore()

        /* Create Alice's group cipher */
        let aliceGroupCipher = GroupCipher(store: aliceStore, senderKeyId: aliceSenderName)

        /* Try to encrypt without a session */
        do {
            let plaintext = "up the punks".asByteArray
            let _ = try aliceGroupCipher.encrypt(paddedPlaintext: plaintext)
            XCTFail("Should fail with error")
            return
        } catch let error as SignalError where error == .noSession {

        } catch {
            XCTFail("Should fail with different error")
            return
        }
    }

    func testTooFarInFuture() {
        guard let (aliceCipher, bobCipher) = createWorkingSession() else {
            return
        }

        /* Have Alice encrypt a batch of 2001 messages */
        let plaintext = "up the punks".asByteArray
        for _ in 0..<2001 {
            guard let _ = try? aliceCipher.encrypt(paddedPlaintext: plaintext) else {
                XCTFail("Could not encrypt message")
                return
            }
        }
        /* Have Alice encrypt a message too far in the future */
        let tooFarText = "notta gonna worka".asByteArray
        guard let tooFar = try? aliceCipher.encrypt(paddedPlaintext: tooFarText) else {
            XCTFail("Could not encrypt message")
            return
        }
        /* Have Bob try, and fail, to decrypt the message */
        do {
            let message = try SenderKeyMessage(from: tooFar.data)
            let _ = try bobCipher.decrypt(ciphertext: message)
        } catch let error as SignalError where error == .invalidMessage {

        } catch {
            XCTFail("Failed with wrong error")
            return
        }
    }

    func testMessageKeyLimit() {
        guard let (aliceCipher, bobCipher) = createWorkingSession() else {
            return
        }

        let plaintext = "up the punks".asByteArray
        var inflight = [Data]()
        for _ in 0..<2010 {
            guard let message = try? aliceCipher.encrypt(paddedPlaintext: plaintext) else {
                XCTFail("Could not encrypt message")
                return
            }
            inflight.append(message.data)
        }
        /* Try decrypting in-flight message 1001 */
        do {
            let message1001 = try SenderKeyMessage(from: inflight[1000])
            let _ = try bobCipher.decrypt(ciphertext: message1001)
        } catch {
            XCTFail("Could not decrypt message 1001")
            return
        }

        /* Try decrypting in-flight message 2010 */
        do {
            let message1001 = try SenderKeyMessage(from: inflight[2009])
            let _ = try bobCipher.decrypt(ciphertext: message1001)
        } catch {
            XCTFail("Could not decrypt message 2010")
            return
        }

        /* Try decrypting in-flight message 0, which should fail */
        do {
            let message1001 = try SenderKeyMessage(from: inflight[2009])
            let _ = try bobCipher.decrypt(ciphertext: message1001)
            XCTFail("Should not decrypt message 0")
        } catch let error as SignalError where error == .duplicateMessage {

        } catch {
            XCTFail("Should fail to decrypt message with different error")
            return
        }
    }

    func testInvalidSignatureKey() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the session builders */
        let aliceSessionBuilder = GroupSessionBuilder(store: aliceStore)
        let bobSessionBuilder = GroupSessionBuilder(store: bobStore)

        /* Create the group ciphers */
        let bobGroupCipher = GroupCipher(store: bobStore, senderKeyId: groupSender)

        /* Create Alice's sender key distribution message */
        guard let aliceDistributionMessage =
            try? aliceSessionBuilder.createSession(senderKeyName: groupSender) else {
                XCTFail("Could not create distribution message")
                return
        }
        /* Processing Alice's distribution message */
        do {
            try bobSessionBuilder.processSession(
                senderKeyName: groupSender,
                distributionMessage: aliceDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }

        /* Encrypt a test message from Bob, which should fail because no message was received from Alice yet */
        let plaintext = "smert ze smert".asByteArray
        do {
            let _ = try bobGroupCipher.encrypt(paddedPlaintext: plaintext)
            XCTFail("Should fail to decrypt")
            return
        } catch let error as SignalError where error == .invalidKey {

        } catch {
            XCTFail("Failed with wrong error")
            return
        }

    }
    
}
