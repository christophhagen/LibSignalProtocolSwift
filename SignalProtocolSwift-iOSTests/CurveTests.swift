//
//  CurveTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 24.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocolSwift

// The result from forming an agreement between alice and bob
private let shared = Data([
    0x32, 0x5f, 0x23, 0x93, 0x28, 0x94, 0x1c, 0xed, 0x6e, 0x67, 0x3b,
    0x86, 0xba, 0x41, 0x01, 0x74, 0x48, 0xe9, 0x9b, 0x64, 0x9a, 0x9c,
    0x38, 0x06, 0xc1, 0xdd, 0x7c, 0xa4, 0xc4, 0x77, 0xe6, 0x29])

class CurveTests: XCTestCase {

    func testFastSHA512() {
        guard sha512_fast_test(1) == 0 else {
            XCTFail("SHA512 fast test failed")
            return
        }
    }

    func testFastStrict() {
        guard strict_fast_test(1) == 0 else {
                XCTFail("Strict fast test failed")
                return
        }
    }

    func testFastElligator() {
        guard elligator_fast_test(1) == 0 else {
                XCTFail("Elligator fast test failed")
                return
        }
    }

    func testFastCurveSigs() {
        guard curvesigs_fast_test(1) == 0 else {
                XCTFail("CurveSigs fast test failed")
                return
        }
    }

    func testFastXEdDSA() {
        guard xeddsa_fast_test(1) == 0 else {
                XCTFail("XEdDSA fast test failed")
                return
        }
    }

    func testFastGeneralizedXEdDSA() {
        guard generalized_xeddsa_fast_test(1) == 0 else {
                XCTFail("Generalized XEdDSA fast test failed")
                return
        }
    }

    func testFastGeneralizedXVEdDSA() {
        guard generalized_xveddsa_fast_test(1) == 0 else {
                XCTFail("Generalized XVEdDSA fast test failed")
                return
        }
    }

    func testCurveSigs() {
        guard curvesigs_slow_test(1, 10000) == 0 else {
                XCTFail("CurveSigs slow tests failed")
                return
        }
    }

    func testXEdDSASlow() {
        guard xeddsa_slow_test(1, 10000) == 0 else {
                XCTFail("XEdDSA slow tests failed")
                return
        }
    }
    func testXEdDSAtoCurveSigs() {
        guard xeddsa_to_curvesigs_slow_test(1, 10000) == 0 else {
                XCTFail("XEdDSA to CurveSigs slow tests failed")
                return
        }
    }

    func testXVEdDSA() {
        guard generalized_xveddsa_slow_test(1, 10000) == 0 else {
                XCTFail("XVEdDSA slow tests failed")
                return
        }
    }

    func testCurveSignature()  {

        let message = [UInt8](repeating: 0, count: 16)
        guard let keyPair = try? KeyPair() else {
            XCTFail("Could not create key pair")
            return
        }

        guard let random = try? SignalCrypto.random(bytes: 64) else {
            XCTFail("Could not get random bytes")
            return
        }

        var signature = [UInt8](repeating: 0, count: 64)
        let length = message.count
        guard length > 0, length < 256 else {
            XCTFail("Invalid length")
            return
        }

        let result: Int32 = keyPair.privateKey.data.withUnsafeBytes { ptr in
            random.withUnsafeBytes { randomPtr in
                curve25519_sign(&signature, ptr, message, UInt(length), randomPtr)
            }
        }
        guard result == 0 else {
            XCTFail("Could not sign message")
            return
        }

        let result2 = keyPair.publicKey.data.advanced(by: 1).withUnsafeBytes {
            curve25519_verify(&signature, $0, message, UInt(length))
        }
        guard result2 == 0 else {
            XCTFail("Could not verify message")
            return
        }
    }

    /**
     Test if signatures and verification work
     */
    func testKeySignature() {
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
     Test if Diffie-Hellman agreements can be correctly calculated
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
