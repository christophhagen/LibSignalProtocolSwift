//
//  CurveTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 24.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
import Curve25519
@testable import SignalProtocolSwift

// The result from forming an agreement between alice and bob
private let shared = Data([
    0x32, 0x5f, 0x23, 0x93, 0x28, 0x94, 0x1c, 0xed, 0x6e, 0x67, 0x3b,
    0x86, 0xba, 0x41, 0x01, 0x74, 0x48, 0xe9, 0x9b, 0x64, 0x9a, 0x9c,
    0x38, 0x06, 0xc1, 0xdd, 0x7c, 0xa4, 0xc4, 0x77, 0xe6, 0x29])

class CurveTests: XCTestCase {

    /**
     Test if signing and verification works
     */
    func testSignature() {
        let testMessage = Data([UInt8]("WhisperTextMessage".utf8))

        guard let keyPair = try? KeyPair() else {
            XCTFail("Could not create keys")
            return
        }

        guard let signature = try? keyPair.privateKey.sign(message: testMessage) else {
            XCTFail("Could not sign message")
            return
        }

        guard keyPair.publicKey.verify(signature: signature, for: testMessage) else {
            XCTFail("Could not verify message \(signature.count)")
            return
        }
    }

    /**
     Test if key agreements can be correctly calculated
    */
    func testCurve25519Agreement() {

        guard let (alice, bob) = try? createBobAndAlice() else {
            XCTFail("Could not create keys for bob and alice")
            return
        }

        guard let sharedOne = try? alice.publicKey.calculateAgreement(privateKey: bob.privateKey),
            let sharedTwo = try? bob.publicKey.calculateAgreement(privateKey: alice.privateKey) else {
            XCTFail("Could not calculate agreements")
            return
        }

        guard sharedOne == shared,
            sharedTwo == shared else {
            XCTFail("Agreements not correct")
            return
        }
    }

    /**
     Test if public keys are correctly created from private keys
    */
    func testGeneratePublic() {

        guard let (alice, _) = try? createBobAndAlice() else {
            XCTFail("Could not create keys for bob and alice")
            return
        }

        guard let alicePublicKey = try? PublicKey(privateKey: alice.privateKey) else {
            XCTFail("Alice public key creation failed")
            return
        }

        guard alice.publicKey == alicePublicKey else {
            XCTFail("Public key is not correct")
            return
        }
    }
}
