//
//  GroupCipherTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 09.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocol

private let groupSender = SignalSenderKeyName(
    groupId: "nihilist history reading group",
    sender: SignalAddress(identifier: "+14150001111", deviceId: 1))

class GroupCipherTests: XCTestCase {

    func testNoSession() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(address: groupSender, store: aliceStore)
        let bobGroupCipher = GroupCipher(address: groupSender, store: bobStore)
        
        /* Create the sender key distribution messages */
        guard let sentAliceDistributionMessage =
            try? aliceGroupCipher.createSession() else {
                XCTFail("Could not create distribution message")
                return
        }
        guard let serialized = try? sentAliceDistributionMessage.protoData() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let _ = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Intentionally omitting Bob's processing of received_alice_distribution_message */
        
        /* Encrypt a test message from Alice */
        let alicePlaintext = "smert ze smert".data(using: .utf8)!

        guard let message = try? aliceGroupCipher.encrypt(alicePlaintext) else {
            XCTFail("could not encrypt message")
            return
        }
        
        /* Attempt to have Bob decrypt the message */
        do {
            let senderKeyMessage = try SenderKeyMessage(from: message.data)
            let _ = try bobGroupCipher.decrypt(ciphertext: senderKeyMessage)
            XCTFail("Did not fail to decrypt message")
        } catch let error as SignalError where error.type == .noSession {
            
        } catch {
            XCTFail("Did not fail to decrypt message with correct error")
            return
        }
    }
    
    func testBasicEncryptDecrypt() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(address: groupSender, store: aliceStore)
        let bobGroupCipher = GroupCipher(address: groupSender, store: bobStore)
        
        /* Create the sender key distribution messages */
        guard let sentAliceDistributionMessage =
            try? aliceGroupCipher.createSession() else {
                XCTFail("Could not create distribution message")
                return
        }
        guard let serialized = try? sentAliceDistributionMessage.protoData() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let receivedDistributionMessage = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Processing Alice's distribution message */
        do {
            try bobGroupCipher.process(distributionMessage: receivedDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }
        
        /* Encrypt a test message from Alice */
        let alicePlaintext = "smert ze smert".data(using: .utf8)!
        guard let encrypted = try? aliceGroupCipher.encrypt(alicePlaintext) else {
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
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(address: groupSender, store: aliceStore)
        let bobGroupCipher = GroupCipher(address: groupSender, store: bobStore)
        
        /* Create the sender key distribution messages */
        guard let sentAliceDistributionMessage =
            try? aliceGroupCipher.createSession() else {
                XCTFail("Could not create distribution message")
                return
        }
        guard let serialized = try? sentAliceDistributionMessage.protoData() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let receivedDistributionMessage = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Processing Alice's distribution message */
        do {
            try bobGroupCipher.process(distributionMessage: receivedDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }
        
        /* Prepare some text to encrypt */
        let alicePlaintext = "smert ze smert".data(using: .utf8)!
        let alicePlaintext2 = "smert ze smert2".data(using: .utf8)!
        let alicePlaintext3 = "smert ze smert3".data(using: .utf8)!
        
        /* Encrypt a series of messages from Alice */
        guard let ciphertext1 = try? aliceGroupCipher.encrypt(alicePlaintext),
            let ciphertext2 = try? aliceGroupCipher.encrypt(alicePlaintext2),
            let ciphertext3 = try? aliceGroupCipher.encrypt(alicePlaintext3) else {
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
            } catch let error as SignalError where error.type == .duplicateMessage {
                
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

        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(address: groupSender, store: aliceStore)
        
        /* Create the sender key distribution messages */
        guard let _ =
            try? aliceGroupCipher.createSession() else {
                XCTFail("Could not create distribution message")
                return
        }
        
        /* Pretend this was sent to some people other than Bob */
        for i in 0..<100 {
            let alicePlaintext = "up the punks up the punks up the punks".data(using: .utf8)!
            guard let _ = try? aliceGroupCipher.encrypt(alicePlaintext) else {
                XCTFail("Could not encrypt message \(i)")
                return
            }
        }
        
        
        /* Now Bob Joins */
        let bobGroupCipher = GroupCipher(address: groupSender, store: bobStore)
        
        /* Create Alice's sender key distribution message for Bob */
        guard let sentAliceDistributionMessage =
            try? aliceGroupCipher.createSession() else {
                XCTFail("Could not create distribution message")
                return
        }

        guard let serialized = try? sentAliceDistributionMessage.protoData() else {
            XCTFail("Could not serialize SenderKeyDistributionMessage")
            return
        }

        guard let receivedDistributionMessage = try? SenderKeyDistributionMessage(from: serialized) else {
            XCTFail("Could not deserialize SenderKeyDistributionMessage")
            return
        }
        
        /* Have Bob process Alice's distribution message */
        do {
            try bobGroupCipher.process(distributionMessage: receivedDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }
        
        /* Alice sends a message welcoming Bob */
        do {
            let plaintext = "welcome to the group".data(using: .utf8)!
            let ciphertext = try aliceGroupCipher.encrypt(plaintext)
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

    private func createWorkingSession() -> (GroupCipher<TestStore>, GroupCipher<TestStore>)? {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the group ciphers */
        let aliceGroupCipher = GroupCipher(address: groupSender, store: aliceStore)
        let bobGroupCipher = GroupCipher(address: groupSender, store: bobStore)

        /* Create Alice's sender key distribution message */
        guard let aliceDistributionMessage =
            try? aliceGroupCipher.createSession() else {
                XCTFail("Could not create distribution message")
                return nil
        }

        /* Have Bob process the distribution message */
        do {
            try bobGroupCipher.process(distributionMessage: aliceDistributionMessage)
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
        let plaintext = "up the punks".data(using: .utf8)!
        var ciphertexts = [Data]()
        for _ in 0..<100 {
            guard let message = try? aliceCipher.encrypt(plaintext) else {
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
            groupId: "coolio groupio", sender: SignalAddress(identifier: "+10002223333", deviceId: 1))

        /* Create the test data store for Alice */
        let aliceStore = TestStore()

        /* Create Alice's group cipher */
        let aliceGroupCipher = GroupCipher(address: aliceSenderName, store: aliceStore)

        /* Try to encrypt without a session */
        do {
            let plaintext = "up the punks".data(using: .utf8)!
            let _ = try aliceGroupCipher.encrypt(plaintext)
            XCTFail("Should fail with error")
            return
        } catch let error as SignalError where error.type == .noSession {

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
        let plaintext = "up the punks".data(using: .utf8)!
        for _ in 0..<2001 {
            guard let _ = try? aliceCipher.encrypt(plaintext) else {
                XCTFail("Could not encrypt message")
                return
            }
        }
        /* Have Alice encrypt a message too far in the future */
        let tooFarText = "notta gonna worka".data(using: .utf8)!
        guard let tooFar = try? aliceCipher.encrypt(tooFarText) else {
            XCTFail("Could not encrypt message")
            return
        }
        /* Have Bob try, and fail, to decrypt the message */
        do {
            let message = try SenderKeyMessage(from: tooFar.data)
            let _ = try bobCipher.decrypt(ciphertext: message)
        } catch let error as SignalError where error.type == .invalidMessage {

        } catch {
            XCTFail("Failed with wrong error")
            return
        }
    }

    func testMessageKeyLimit() {
        guard let (aliceCipher, bobCipher) = createWorkingSession() else {
            return
        }

        let plaintext = "up the punks".data(using: .utf8)!
        var inflight = [Data]()
        for _ in 0..<2010 {
            guard let message = try? aliceCipher.encrypt(plaintext) else {
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
        } catch let error as SignalError where error.type == .duplicateMessage {

        } catch {
            XCTFail("Should fail to decrypt message with different error")
            return
        }
    }

    func testInvalidSignatureKey() {
        /* Create the test data stores */
        let aliceStore = TestStore()
        let bobStore = TestStore()
        /* Create the group ciphers */
        let bobGroupCipher = GroupCipher(address: groupSender, store: bobStore)
        let aliceGroupCipher = GroupCipher(address: groupSender, store: aliceStore)


        /* Create Alice's sender key distribution message */
        guard let aliceDistributionMessage =
            try? aliceGroupCipher.createSession() else {
                XCTFail("Could not create distribution message")
                return
        }
        /* Processing Alice's distribution message */
        do {
            try bobGroupCipher.process(distributionMessage: aliceDistributionMessage)
        } catch {
            XCTFail("Could not process distribution message")
            return
        }

        /* Encrypt a test message from Bob, which should fail because no message was received from Alice yet */
        let plaintext = "smert ze smert".data(using: .utf8)!
        do {
            let _ = try bobGroupCipher.encrypt(plaintext)
            XCTFail("Should fail to decrypt")
            return
        } catch let error as SignalError where error.type == .invalidKey {

        } catch {
            XCTFail("Failed with wrong error")
            return
        }

    }
    
}
