//
//  CurveTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 24.10.17.
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

class CurveTests: XCTestCase {

    func testFastInternal() {
        guard sha512_fast_test(1) == 0,
        strict_fast_test(1) == 0,
        elligator_fast_test(1) == 0,
        curvesigs_fast_test(1) == 0,
        xeddsa_fast_test(1) == 0,
        generalized_xeddsa_fast_test(1) == 0,
        generalized_xveddsa_fast_test(1) == 0 else {
            XCTFail("Internal fast tests failed")
            return
        }
    }

    func testSlowInternal() {
        guard curvesigs_slow_test(1, 10000) == 0,
            xeddsa_slow_test(1, 10000) == 0,
            xeddsa_to_curvesigs_slow_test(1, 10000) == 0,
            generalized_xveddsa_slow_test(1, 10000) == 0 else {
                XCTFail("Internal slow tests failed")
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

        let result = curve25519_sign(&signature, keyPair.privateKey.key, message, UInt(length), random)
        guard result == 0 else {
            XCTFail("Could not sign message")
            return
        }

        let result2 = curve25519_verify(&signature, keyPair.publicKey.key, message, UInt(length))
        guard result2 == 0 else {
            XCTFail("Could not verify message")
            return
        }
    }

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
    
    func testCurve25519Agreement() {

        let bobPublic: [UInt8] = [
            0x05, 0x65, 0x36, 0x14, 0x99,
            0x3d, 0x2b, 0x15, 0xee, 0x9e,
            0x5f, 0xd3, 0xd8, 0x6c, 0xe7,
            0x19, 0xef, 0x4e, 0xc1, 0xda,
            0xae, 0x18, 0x86, 0xa8, 0x7b,
            0x3f, 0x5f, 0xa9, 0x56, 0x5a,
            0x27, 0xa2, 0x2f]

        let bobPrivate: [UInt8] = [
            0xb0, 0x3b, 0x34, 0xc3, 0x3a,
            0x1c, 0x44, 0xf2, 0x25, 0xb6,
            0x62, 0xd2, 0xbf, 0x48, 0x59,
            0xb8, 0x13, 0x54, 0x11, 0xfa,
            0x7b, 0x03, 0x86, 0xd4, 0x5f,
            0xb7, 0x5d, 0xc5, 0xb9, 0x1b,
            0x44, 0x66]

        let shared: [UInt8] = [
            0x32, 0x5f, 0x23, 0x93, 0x28,
            0x94, 0x1c, 0xed, 0x6e, 0x67,
            0x3b, 0x86, 0xba, 0x41, 0x01,
            0x74, 0x48, 0xe9, 0x9b, 0x64,
            0x9a, 0x9c, 0x38, 0x06, 0xc1,
            0xdd, 0x7c, 0xa4, 0xc4, 0x77,
            0xe6, 0x29]

        guard let alicePublicKey = try? PublicKey(point: alicePublic) else {
            XCTFail("Alice public key creation failed")
            return
        }

        guard let alicePrivateKey = try? PrivateKey(point: alicePrivate) else {
            XCTFail("Alice private key creation failed")
            return
        }

        guard let bobPublicKey = try? PublicKey(point: bobPublic) else {
            XCTFail("bob public key creation failed")
            return
        }

        guard let bobPrivateKey = try? PrivateKey(point: bobPrivate) else {
            XCTFail("bob private key creation failed")
            return
        }

        guard let sharedOne = try? alicePublicKey.calculateAgreement(privateKey: bobPrivateKey) else {
            XCTFail("Agreement 1 failed")
            return
        }

        guard let sharedTwo = try? bobPublicKey.calculateAgreement(privateKey: alicePrivateKey) else {
            XCTFail("Agreement 2 failed")
            return
        }

        guard sharedOne == shared else {
            XCTFail("Agreement 1 not equal")
            return
        }

        guard sharedTwo == shared else {
            XCTFail("Agreement 2 not equal")
            return
        }
    }

    func testGeneratePublic() {

        guard let alicePrivateKey = try? PrivateKey(point: alicePrivate) else {
            XCTFail("Alice private key creation failed")
            return
        }

        guard let aliceExpectedPublicKey = try? PublicKey(point: alicePublic) else {
            XCTFail("Alice public key creation failed")
            return
        }

        guard let alicePublicKey = try? PublicKey(privateKey: alicePrivateKey) else {
            XCTFail("Alice public key creation failed")
            return
        }

        guard aliceExpectedPublicKey == alicePublicKey else {
            XCTFail("Public keys are not equal")
            return
        }
    }
}
