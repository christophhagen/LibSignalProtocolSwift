//
//  FingerprintTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 11.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocol

private let aliceIdentityData = Data([
    0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d,
    0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e, 0x92,
    0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc,
    0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68])

private let bobIdentityData = Data([
    0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba,
    0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d, 0xa2,
    0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02,
    0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b])

private let displayableFingerprint = "300354477692869396892869876765458257569162576843440918079131"

private let aliceScannableFingerprint = Data([
    0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30,
    0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68,
    0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc,
    0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30,
    0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22,
    0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15,
    0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac,
    0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8,
    0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb,
    0x3a, 0x4d])

private let bobScannableFingerprint = Data([
    0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c,
    0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b,
    0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a,
    0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6,
    0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22,
    0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc,
    0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e,
    0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19,
    0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd,
    0x61, 0xdf])

private let aliceId = "+14152222222"
private let bobId = "+14153333333"

class FingerprintTests: XCTestCase {

    func testScannableFingerprintSerialize() {
        guard let aliceIdentity = try? KeyPair().publicKey,
            let bobIdentity = try? KeyPair().publicKey else {
                XCTFail("Could not create keys")
                return
        }
        let aliceScannable: ScannableFingerprint
        let bobScannable: ScannableFingerprint
        do {
            aliceScannable = try ScannableFingerprint(
                localFingerprint: aliceIdentity.data, remoteFingerprint: bobIdentity.data)
            bobScannable = try ScannableFingerprint(
                localFingerprint: bobIdentity.data, remoteFingerprint: aliceIdentity.data)
        } catch {
            XCTFail("Could not create scannable fingerprint")
            return
        }

        guard aliceScannable.matches(bobScannable) else {
            XCTFail("Fingerprints don't match")
            return
        }

        guard let serialized = try? bobScannable.protoData() else {
            XCTFail("Could not serialize fingerprint")
            return
        }
        guard let deserialized = try? ScannableFingerprint(from: serialized) else {
            XCTFail("Could not deserialize fingerprint")
            return
        }

        guard aliceScannable.matches(deserialized) else {
            XCTFail("Fingerprints don't match")
            return
        }
    }

    func vectorTest() {
        guard let aliceIdentity = try? PublicKey(point: aliceIdentityData),
            let bobIdentity = try? PublicKey(point: bobIdentityData) else {
                XCTFail("Could not create keys")
                return
        }
        guard let aliceFingerprint = try? Fingerprint(
            localStableIdentifier: aliceId, localIdentity: aliceIdentity,
            remoteStableIdentifier: bobId, remoteIdentity: bobIdentity,
            iterations: 5200) else {
                XCTFail("Could not create fingerprint for Alice")
                return
        }
        guard let bobFingerprint = try? Fingerprint(
            localStableIdentifier: bobId, localIdentity: bobIdentity,
            remoteStableIdentifier: aliceId, remoteIdentity: aliceIdentity,
            iterations: 5200) else {
                XCTFail("Could not create fingerprint for Bob")
                return
        }
        guard aliceFingerprint.displayable.displayText == displayableFingerprint,
            bobFingerprint.displayable.displayText == displayableFingerprint else {
                XCTFail("Displayable fingerprints invalid")
                print(aliceFingerprint.displayable.displayText)
                print(bobFingerprint.displayable.displayText)
                print(displayableFingerprint)
                return
        }

        guard let aliceSerialized = try? aliceFingerprint.scannable.protoData(),
            let bobSerialized = try? bobFingerprint.scannable.protoData() else {
                XCTFail("Could not serialize scannable fingerprints")
                return
        }
        guard aliceSerialized == aliceScannableFingerprint,
            bobSerialized == bobScannableFingerprint else {
                XCTFail("Serialized fingerprint invalid")
                return
        }
    }

    private func compareFingerprints(aliceFingerprint: Fingerprint, bobFingerprint: Fingerprint) {
        guard aliceFingerprint.displayable.displayText == bobFingerprint.displayable.displayText else {
            XCTFail("Displayable fingerprints don't match")
            return
        }
        guard aliceFingerprint.scannable.matches(bobFingerprint.scannable),
            bobFingerprint.scannable.matches(aliceFingerprint.scannable) else {
                XCTFail("Scannable fingerprints don't match")
                return
        }
        guard aliceFingerprint.displayable.displayText.utf8.count == 60 else {
            XCTFail("Displayable fingerprint length invalid")
            return
        }
    }

    func testMatchingFingerprints() {
        guard let aliceIdentity = try? PublicKey(point: aliceIdentityData),
            let bobIdentity = try? PublicKey(point: bobIdentityData) else {
                XCTFail("Could not create keys")
                return
        }
        guard let aliceFingerprint = try? Fingerprint(
            localStableIdentifier: aliceId, localIdentity: aliceIdentity,
            remoteStableIdentifier: bobId, remoteIdentity: bobIdentity,
            iterations: 1024) else {
                XCTFail("Could not create fingerprint for Alice")
                return
        }
        guard let bobFingerprint = try? Fingerprint(
                localStableIdentifier: bobId, localIdentity: bobIdentity,
                remoteStableIdentifier: aliceId, remoteIdentity: aliceIdentity,
                iterations: 1024) else {
                XCTFail("Could not create fingerprint for Bob")
                return
        }

        compareFingerprints(aliceFingerprint: aliceFingerprint, bobFingerprint: bobFingerprint)
    }

    func testMatchingFingerprintLists() {
        var aliceKeyList = [PublicKey]()
        var bobKeyList = [PublicKey]()
        do {
            for _ in 0..<4 {
                aliceKeyList.append(try KeyPair().publicKey)
                bobKeyList.append(try KeyPair().publicKey)
            }
        } catch {
            XCTFail("Could not create keys")
            return
        }
        guard let aliceFingerprint = try? Fingerprint(
            localStableIdentifier: aliceId, localIdentityList: aliceKeyList,
            remoteStableIdentifier: bobId, remoteIdentityList: bobKeyList,
            iterations: 1024) else {
                XCTFail("Could not create fingerprint for alice")
                return
        }

        guard let bobFingerprint = try? Fingerprint(
            localStableIdentifier: bobId, localIdentityList: bobKeyList,
            remoteStableIdentifier: aliceId, remoteIdentityList: aliceKeyList,
            iterations: 1024) else {
                XCTFail("Could not create fingerprint for bob")
                return
        }

        compareFingerprints(aliceFingerprint: aliceFingerprint, bobFingerprint: bobFingerprint)
    }

    func testMismatchingFingerprints() {
        guard let aliceIdentity = try? KeyPair().publicKey,
            let bobIdentity = try? KeyPair().publicKey,
            let mitmIdentity = try? KeyPair().publicKey else {
                XCTFail("Could not create keys")
                return
        }
        guard let aliceFingerprint = try? Fingerprint(
            localStableIdentifier: aliceId, localIdentity: aliceIdentity,
            remoteStableIdentifier: bobId, remoteIdentity: mitmIdentity,
            iterations: 1024) else {
                XCTFail("Could not create fingerprint for Alice")
                return
        }
        guard let bobFingerprint = try? Fingerprint(
            localStableIdentifier: bobId, localIdentity: bobIdentity,
            remoteStableIdentifier: aliceId, remoteIdentity: aliceIdentity,
            iterations: 1024) else {
                XCTFail("Could not create fingerprint for Bob")
                return
        }
        guard aliceFingerprint.displayable.displayText != bobFingerprint.displayable.displayText else {
            XCTFail("Displayable fingerprints shouldn't match")
            return
        }

        guard aliceFingerprint.scannable.matches(bobFingerprint.scannable) == false else {
            XCTFail("Scannable fingerprints shouldn't match")
            return
        }
    }

    func testMismatchingIdentifiers() {
        guard let aliceIdentity = try? KeyPair().publicKey,
            let bobIdentity = try? KeyPair().publicKey else {
                XCTFail("Could not create keys")
                return
        }
        guard let aliceFingerprint = try? Fingerprint(
            localStableIdentifier: aliceId + "2", localIdentity: aliceIdentity,
            remoteStableIdentifier: bobId, remoteIdentity: bobIdentity,
            iterations: 1024) else {
                XCTFail("Could not create fingerprint for Alice")
                return
        }
        guard let bobFingerprint = try? Fingerprint(
            localStableIdentifier: bobId, localIdentity: bobIdentity,
            remoteStableIdentifier: aliceId, remoteIdentity: aliceIdentity,
            iterations: 1024) else {
                XCTFail("Could not create fingerprint for Bob")
                return
        }
        guard aliceFingerprint.displayable.displayText != bobFingerprint.displayable.displayText else {
            XCTFail("Displayable fingerprints shouldn't match")
            return
        }
        guard aliceFingerprint.scannable.matches(bobFingerprint.scannable) == false else {
            XCTFail("Should fail to match fingerprints")
            return
        }
        guard bobFingerprint.scannable.matches(aliceFingerprint.scannable) == false else {
            XCTFail("Should fail to match fingerprints")
            return
        }
    }
}
