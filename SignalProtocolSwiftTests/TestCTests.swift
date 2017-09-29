//
//  TestCTests.swift
//  TestCTests
//
//  Created by User on 17.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import TestC

let aliceAddress = CHAddress(deviceID: 1, recipientID: "+14151111111")
let bobAddress = CHAddress(deviceID: 1, recipientID: "+14152222222")

class TestCTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testCreationAndCommunication() {
        guard let alice = SignalInterface(keyStore: TestKeyStore()) else {
            XCTFail("Could not create SignalInterface for Alice")
            return
        }

        guard let bob = SignalInterface(keyStore: TestKeyStore()) else {
            XCTFail("Could not create SignalInterface for Bob")
            return
        }

        guard let (bobPreKeyBundle, bobPreKey) = bob.generatePreKeyBundleAndPreKey(deviceID: 1, signedPreKeyID: 22) else {
            XCTFail("Could not create Pre Key Bundle and Pre Key for Bob")
            return
        }

        let plaintext = "Yo yo yo, what's up?"
        guard let ciphertext = alice.encryptInitial(text: plaintext, to: bobAddress, with: bobPreKeyBundle, and: bobPreKey) else {
            XCTFail("Could not encrypt initial message from Alice to Bob")
            return
        }

        guard let decryptedMessage = bob.decryptText(ciphertext, from: aliceAddress) else {
            XCTFail("Could not decrypt initial message from Alice")
            return
        }

        guard plaintext == decryptedMessage else {
            XCTFail("Initial message not received correctly")
            return
        }

        let plaintext2 = "I'm good. What's up with you?"
        guard let ciphertext2 = bob.encrypt(text: plaintext2, to: aliceAddress) else {
            XCTFail("Could not encrypt message from Bob to Alice")
            return
        }

        guard let decryptedMessage2 = alice.decryptText(ciphertext2, from: bobAddress) else {
            XCTFail("Could not decrypt message from Bob to Alice")
            return
        }

        guard plaintext2 == decryptedMessage2 else {
            XCTFail("Second message doesn't match")
            return
        }

        /* Create new KeyStore for Alice, changes identity */
        guard let alice2 = SignalInterface(keyStore: TestKeyStore()) else {
            XCTFail("Could not create new SignalInterface for Alice")
            return
        }

        /** Create Pre Key bundle and Pre Key for new Session */
        guard let (bobPreKeyBundle2, bobPreKey2) = bob.generatePreKeyBundleAndPreKey(deviceID: 1, signedPreKeyID: 23) else {
            XCTFail("Could not create new Pre Key Bundle and Pre Key for Bob")
            return
        }

        let plaintext3 = "I changed my phone, so new id"
        guard let ciphertext3 = alice2.encryptInitial(text: plaintext3, to: bobAddress, with: bobPreKeyBundle2, and: bobPreKey2) else {
            XCTFail("Could not encrypt initial message from Alice to Bob")
            return
        }

        if let _ = bob.decryptText(ciphertext3, from: aliceAddress) {
            XCTFail("Should not be decrypted without error because identity changed")
        }

        guard let decryptedMessage3 = bob.decryptText(ciphertext3, from: aliceAddress, trustNewIdentity: true) else {
            XCTFail("Could not decrypt message after identity change")
            return
        }

        guard plaintext3 == decryptedMessage3 else {
            XCTFail("Plaintext doesn't match for message after identity key change")
            return
        }

        /*
        // Create a new identity key for bob
        guard let identity = SignalInterface.generateIdentityKeyPair() else {
            XCTFail("Could not create new identity key")
            return
        }
        let registrationID = bob.identityKeyStore.localRegistrationID
        bobStore.keyStore.identityKeyStoreDelegate = TestIdentityKeyStore(identity: identity, registrationID: registrationID)


        guard let bobPreKeyBundleNew2 = try? bobSession.generatePreKeyBundle(deviceID: 1, preKeyID: 31337, signedPreKeyID: 23) else {
            XCTFail("Could not create new Pre Key Bundle for Bob")
            return
        }

        do {
            let _ = try aliceSession.encryptInitial(message: plaintext3, to: bobAddress, with: bobPreKeyBundleNew2)
            XCTFail("Should not accept new pre key bundle")
        } catch let SignalError.failProcessPreKeyBundle(error) where error == SG_ERR_UNTRUSTED_IDENTITY {

        } catch {
            XCTFail("Should not accept new pre key bundle")
        }
 */
    }

    func testPreKeyBundles() {
        /*
        guard let aliceSession = try? SignalInterface() else {
            XCTFail("Could not create SignalInterface for Alice")
            return
        }

        /* Create Alice's data store */
        guard let aliceStore = TestKeyStore() else {
            XCTFail("Could not create KeyStore for Alice")
            return
        }
        aliceSession.store = aliceStore.keyStore

        let _ = try? aliceSession.generatePreKeyBundle2(deviceID: 1, signedPreKeyID: 23485)

        let preKey = try? aliceSession.generatePreKey(id: 23456)

        print("\(String(describing: preKey?.count))")

        guard let bundle1 = try? aliceSession.generatePreKeyBundle(deviceID: 1, preKeyID: 1, signedPreKeyID: 2) else {
            XCTFail("Could not create first bundle")
            return
        }

        guard let bundle2 = try? aliceSession.generatePreKeyBundle(deviceID: 1, preKeyID: 33182, signedPreKeyID: 2) else {
            XCTFail("Could not create second bundle")
            return
        }

        guard bundle1.count == bundle2.count else {
            XCTFail("Lengths are different")
            return
        }

        var manipulatedBundle = bundle1

        // Copy pre key id
        for i in 8..<12 {
            manipulatedBundle[i] = bundle2[i]
        }

        // Copy pre key
        for i in 16..<50 {
            manipulatedBundle[i] = bundle2[i]
        }

        guard let bobSession = try? SignalInterface() else {
            XCTFail("Could not create SignalInterface for Alice")
            return
        }

        /* Create Bob's data store */
        guard let bobStore = TestKeyStore() else {
            XCTFail("Could not create KeyStore for Alice")
            return
        }
        bobSession.store = bobStore.keyStore

        let plaintext = [UInt8]("Yo yo yo, what's up?".utf8)

        guard let ciphertext = try? bobSession.encryptInitial(message: plaintext, to: aliceAddress, with: manipulatedBundle) else {
            XCTFail("Could not initiate session")
            return
        }

        guard let decrypted = try? aliceSession.decrypt(ciphertext, from: bobAddress) else {
            XCTFail("Could not decrypt initial message")
            return
        }

        guard plaintext == decrypted else {
            XCTFail("Messages different")
            return
        }

        //print(String(format: "%3d: %3d - %3d", i, bundle1[i], bundle2[i]))
    }

    func testNewBundles() {
        guard let aliceSession = try? SignalInterface() else {
            XCTFail("Could not create SignalInterface for Alice")
            return
        }

        /* Create Alice's data store */
        guard let aliceStore = TestKeyStore() else {
            XCTFail("Could not create KeyStore for Alice")
            return
        }
        aliceSession.store = aliceStore.keyStore

        guard let bundle = try? aliceSession.generatePreKeyBundle2(deviceID: 1, signedPreKeyID: 12345) else {
            XCTFail()
            return
        }
        guard let preKey = try? aliceSession.generatePreKey(id: 23456) else {
            XCTFail()
            return
        }

        print("\(preKey.count)")

        guard let bobSession = try? SignalInterface() else {
            XCTFail("Could not create SignalInterface for Bob")
            return
        }

        /* Create Alice's data store */
        guard let bobStore = TestKeyStore() else {
            XCTFail("Could not create KeyStore for Bob")
            return
        }
        bobSession.store = bobStore.keyStore

        let plaintext = [UInt8]("Yo yo yo, what's up?".utf8)

        guard let ciphertext = try? bobSession.encryptInitial2(message: plaintext, to: aliceAddress, with: bundle, and: preKey) else {
            XCTFail()
            return
        }
 */
    }
    /*
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {

        }
    }
    */
}
