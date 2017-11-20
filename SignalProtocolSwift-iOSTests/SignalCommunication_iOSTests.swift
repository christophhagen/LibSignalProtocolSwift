//
//  SignalCommunication_iOSTests.swift
//  SignalCommunication-iOSTests
//
//  Created by User on 15.11.17.
//

import XCTest
@testable import SignalProtocolSwift

class SignalCommunication_iOSTests: XCTestCase {

    private let aliceAddress = SignalAddress(identifier: "Alice", deviceId: 1)

    private let bobAddress = SignalAddress(identifier: "Bob", deviceId: 1)


    func testExample() {
        // Create environement for Alice
        let aliceStore = TestStore()
        let aliceIdentity = try! aliceStore.getIdentityKey()

        // Create the server connection for Alice
        let aliceServer = SignalServerConnection(
            store: aliceStore,
            server: TestServer(ownAddress: aliceAddress, signatureKey: aliceIdentity.privateKey))

        do {
            // Upload identity and keys
            try aliceServer.uploadIdentity()
            try aliceServer.uploadNewSignedPreKey()
            try aliceServer.uploadPreKeys()
        } catch {
            // See the documentation for the types of errors that can be thrown here
            XCTFail("Something went wrong")
        }

        // Create environement for Bob
        let bobStore = TestStore()
        let bobIdentity = try! bobStore.getIdentityKey()

        // Create the server connection for Bob
        let bobServer = SignalServerConnection(
            store: bobStore,
            server: TestServer(ownAddress: bobAddress, signatureKey: bobIdentity.privateKey))

        // Set key store to Bob's store
        SignalSession.store = bobStore

        do {
            // Get the PreKeyBundle from the server
            let preKeyBundle = try bobServer.preKeyBundle(for: aliceAddress)

            // Create a new session by processing the PreKeyBundle
            let session = try SignalSession(for: aliceAddress, with: preKeyBundle)

            // Here Alice can send messages to Bob
            let encryptedMessage = try session.encrypt("Hello Alice, it's Bob".data(using: .utf8)!)

            // Upload the message to the server
            try bobServer.upload(message: encryptedMessage, for: aliceAddress)

        } catch let error as SignalError {
            // See the documentation for the types of errors that can be thrown here
            XCTFail("Something went wrong: \(error.description)")
        } catch {
            XCTFail("Something went wrong: \(error)")
        }

        // Set key store to Alice's store
        SignalSession.store = aliceStore

        do {
            // Have Alice retrieve the new messages from the server
            let messages = try aliceServer.messages()

            // Only look at messages from Bob
            guard let bobMessages = messages[bobAddress] else {
                throw SignalError(.invalidId, "No messages from Bob")
            }

            // Create session to decrypt message
            let session = SignalSession(for: bobAddress)

            // Decrypt Bob's messages
            for message in bobMessages {
                let data = try session.decrypt(message)
                print(String(bytes: data, encoding: .utf8)!)
            }

            // Send a message to Bob

        } catch let error as SignalError {
            // See the documentation for the types of errors that can be thrown here
            XCTFail("Something went wrong: \(error.description)")
        } catch {
            XCTFail("Something went wrong: \(error)")
        }
    }

    
}
