//
//  CompatibilityTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocolSwift

private let alicePublic: [UInt8] = [
    0x05, 0x1b, 0xb7, 0x59, 0x66,
    0xf2, 0xe9, 0x3a, 0x36, 0x91,
    0xdf, 0xff, 0x94, 0x2b, 0xb2,
    0xa4, 0x66, 0xa1, 0xc0, 0x8b,
    0x8d, 0x78, 0xca, 0x3f, 0x4d,
    0x6d, 0xf8, 0xb8, 0xbf, 0xa2,
    0xe4, 0xee, 0x28]

private let alicePrivate: [UInt8] = [
    0xc8, 0x06, 0x43, 0x9d, 0xc9,
    0xd2, 0xc4, 0x76, 0xff, 0xed,
    0x8f, 0x25, 0x80, 0xc0, 0x88,
    0x8d, 0x58, 0xab, 0x40, 0x6b,
    0xf7, 0xae, 0x36, 0x98, 0x87,
    0x90, 0x21, 0xb9, 0x6b, 0xb4,
    0xbf, 0x59]

private let bobPublic: [UInt8] = [
    0x05, 0x65, 0x36, 0x14, 0x99,
    0x3d, 0x2b, 0x15, 0xee, 0x9e,
    0x5f, 0xd3, 0xd8, 0x6c, 0xe7,
    0x19, 0xef, 0x4e, 0xc1, 0xda,
    0xae, 0x18, 0x86, 0xa8, 0x7b,
    0x3f, 0x5f, 0xa9, 0x56, 0x5a,
    0x27, 0xa2, 0x2f]

private let ratchetKey: [UInt8] = [
    0x05, 0x1c, 0xb7, 0x59, 0x66,
    0xf2, 0xe9, 0x3a, 0x36, 0x91,
    0xd5, 0xfa, 0x94, 0x2c, 0xb2,
    0x15, 0x66, 0xa1, 0xc0, 0x8b,
    0x8d, 0x73, 0xca, 0x3f, 0x4d,
    0x6d, 0xf8, 0xb8, 0xbf, 0xa2,
    0xe4, 0xee, 0x28]

private let baseKeyPublic: [UInt8] = [
    0x05, 0x1c, 0xb7, 0x59, 0x66,
    0xf2, 0xe9, 0x3a, 0x36, 0x91,
    0xd5, 0xfa, 0x94, 0x2c, 0xb2,
    0x15, 0x66, 0xa1, 0xc0, 0x8b,
    0x8d, 0x73, 0x34, 0x3a, 0xe5,
    0x6d, 0xd0, 0xc3, 0x49, 0x77,
    0xe4, 0xee, 0x28]


class CompatibilityTests: XCTestCase {

    func testSerializeSignalMessage() {
        let correct: [UInt8] = [51,10,33,5,28,183,89,102,242,233,58,54,145,213,250,148,44,178,21,102,161,192,139,141,115,202,63,77,109,248,184,191,162,228,238,40,16,3,24,2,34,15,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,191,53,108,65,168,67,34,241]

        guard let alicePublicKey = try? PublicKey(point: alicePublic) else {
            XCTFail("Alice public key creation failed")
            return
        }

        guard let bobPublicKey = try? PublicKey(point: bobPublic) else {
            XCTFail("bob public key creation failed")
            return
        }

        guard let senderRatchetKey = try? PublicKey(point: ratchetKey) else {
            XCTFail("Alice private key creation failed")
            return
        }

        let ciphertext: [UInt8] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        let macKey: [UInt8] = [9,8,7,6,5,4,3,2]

        do {
            let message = try SignalMessage(messageVersion: 3,
                                        macKey: macKey,
                                        senderRatchetKey: senderRatchetKey,
                                        counter: 3,
                                        previousCounter: 2,
                                        cipherText: ciphertext,
                                        senderIdentityKey: alicePublicKey, receiverIdentityKey: bobPublicKey)

            let record = try message.baseMessage().data
            guard record.count == correct.count else {
                XCTFail("Record length invalid: \(record.count) != \(correct.count)")
                return
            }

            guard let recovered = try? SignalMessage(from: record) else {
                XCTFail("Could not deserialize SignalMessage")
                return
            }

            guard (try? recovered.verifyMac(
                senderIdentityKey: alicePublicKey,
                receiverIdentityKey: bobPublicKey,
                macKey: macKey)) ?? false else {
                    XCTFail("Invalid signature")
                    return
            }
            
            guard recovered.counter == message.counter, recovered.previousCounter == message.previousCounter else {
                XCTFail("Invalid variables")
                return
            }

            guard [UInt8](record) == correct else {
                XCTFail("Records not equal")
                return
            }

        } catch {
            XCTFail("Could not create message: \(error.localizedDescription)")
        }

    }

    func testSerializeSenderKeyMessage() {
        let correct: [UInt8] = [51,8,1,16,17,26,20,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,113,97,15,28,197,27,131,169,235,199,98,2,15,30,95,142,125,250,83,180,85,167,93,120,53,33,55,163,134,244,24,197,86,169,100,251,67,136,246,74,128,244,225,222,243,14,77,134,254,25,158,248,189,83,156,251,253,60,85,0,212,231,190,134]

        guard let alicePrivateKey = try? PrivateKey(point: alicePrivate) else {
            XCTFail("Alice private key creation failed")
            return
        }
        guard let alicePublicKey = try? PublicKey(privateKey: alicePrivateKey) else {
            XCTFail("Alice public key creation failed")
            return
        }

        let ciphertext: [UInt8] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]
        guard let message = try? SenderKeyMessage(
            keyId: 1,
            iteration: 17,
            cipherText: Data(ciphertext),
            signatureKey: alicePrivateKey) else {
                XCTFail("Could not create SenderKeyMessage")
                return
        }

        do {
            let serialized = try message.baseMessage().data

            guard serialized.count == correct.count else {
                XCTFail("Invalid length \(serialized.count) != \(correct.count)")
                return
            }
            let rebuilt = try SenderKeyMessage(from: serialized)
            guard try rebuilt.verify(signatureKey: alicePublicKey) else {
                XCTFail("Invalid signature")
                return
            }
            let other = try SenderKeyMessage(from: Data(correct))
            guard try other.verify(signatureKey: alicePublicKey) else {
                XCTFail("Invalid signature")
                return
            }
            guard rebuilt.keyId == other.keyId, rebuilt.iteration == other.iteration else {
                XCTFail("Properties not equal")
                return
            }
        } catch {
            print(error.localizedDescription)
            XCTFail("Invalid record")
            return
        }
    }

    func testSerializePreKeySignalMessage() {
        let correct: [UInt8] = [51,8,169,18,18,33,5,28,183,89,102,242,233,58,54,145,213,250,148,44,178,21,102,161,192,139,141,115,52,58,229,109,208,195,73,119,228,238,40,26,33,5,27,183,89,102,242,233,58,54,145,223,255,148,43,178,164,102,161,192,139,141,120,202,63,77,109,248,184,191,162,228,238,40,34,65,51,10,33,5,28,183,89,102,242,233,58,54,145,213,250,148,44,178,21,102,161,192,139,141,115,202,63,77,109,248,184,191,162,228,238,40,16,3,24,2,34,15,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,191,53,108,65,168,67,34,241,40,123,48,128,27]

        let alicePublicKey = try! PublicKey(point: alicePublic)
        let bobPublicKey = try! PublicKey(point: bobPublic)
        let senderRatchetKey = try! PublicKey(point: ratchetKey)
        let baseKey = try! PublicKey(point: baseKeyPublic)

        let ciphertext: [UInt8] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        let macKey: [UInt8] = [9,8,7,6,5,4,3,2]

        let message = try! SignalMessage(messageVersion: 3,
                                            macKey: macKey,
                                            senderRatchetKey: senderRatchetKey,
                                            counter: 3,
                                            previousCounter: 2,
                                            cipherText: ciphertext,
                                            senderIdentityKey: alicePublicKey, receiverIdentityKey: bobPublicKey)

        let preKeyMessage = PreKeySignalMessage(messageVersion: 3, registrationId: 123, preKeyId: 2345, signedPreKeyId: 3456, baseKey: baseKey, identityKey: alicePublicKey, message: message)

        guard let record = try? preKeyMessage.baseMessage().data else {
            XCTFail("Could not serialize message")
            return
        }

        guard record.count == correct.count else {
            XCTFail("Invalid length \(record.count) (\(correct.count))")
            return
        }

        guard [UInt8](record) == correct else {
            XCTFail("Invalid record")
            return
        }

    }

    func testSerializeSenderKeyDistributionMessage() {
        let correct: [UInt8] = [51,8,1,16,210,9,26,8,9,8,7,6,5,4,3,2,34,33,5,27,183,89,102,242,233,58,54,145,223,255,148,43,178,164,102,161,192,139,141,120,202,63,77,109,248,184,191,162,228,238,40]

        let signaturePublic: [UInt8] =
            [0x05, 0x1b, 0xb7, 0x59, 0x66,
             0xf2, 0xe9, 0x3a, 0x36, 0x91,
             0xdf, 0xff, 0x94, 0x2b, 0xb2,
             0xa4, 0x66, 0xa1, 0xc0, 0x8b,
             0x8d, 0x78, 0xca, 0x3f, 0x4d,
             0x6d, 0xf8, 0xb8, 0xbf, 0xa2,
             0xe4, 0xee, 0x28]

        let chainKey: [UInt8] = [9,8,7,6,5,4,3,2]

        let signatureKey = try! PublicKey(point: signaturePublic)

        let message = SenderKeyDistributionMessage(id: 1, iteration: 1234, chainKey: chainKey, signatureKey: signatureKey)

        guard let record = try? message.baseMessage().data else {
            XCTFail("Could not serialize message")
            return
        }

        guard record.count == correct.count else {
            XCTFail("Invalid length \(record.count) (\(correct.count))")
            return
        }

        guard [UInt8](record) == correct else {
            XCTFail("Invalid record")
            return
        }
    }
}
