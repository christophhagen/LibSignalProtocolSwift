//
//  TestServer.swift
//  SignalCommunication-iOSTests
//
//  Created by User on 16.11.17.
//

import Foundation
@testable import SignalProtocolSwift

final class TestServer: SignalServer {

    private static var identities = [SignalAddress : PreKeyBundle.Identity]()

    private static var signedKeys = [SignalAddress : PreKeyBundle.SignedPreKey]()

    private static var prekeys = [SignalAddress : [PreKeyBundle.PreKey]]()

    private static var allMessages = [SignalAddress : [SignalAddress : [Data]]]()

    var ownAddress: SignalAddress

    private let signatureKey: PrivateKey

    init(ownAddress: SignalAddress, signatureKey: PrivateKey) {
        self.ownAddress = ownAddress
        self.signatureKey = signatureKey
    }

    func upload(identity: PreKeyBundle.Identity) {
        TestServer.identities[ownAddress] = identity
    }

    func upload(signedPreKey: PreKeyBundle.SignedPreKey) {
        TestServer.signedKeys[ownAddress] = signedPreKey
    }

    func upload(preKeys: [PreKeyBundle.PreKey]) throws {
        TestServer.prekeys[ownAddress]?.append(contentsOf: preKeys)
    }

    func preKeyCount() throws -> Int {
        return TestServer.prekeys[ownAddress]?.count ?? 0
    }

    func messages() -> [SignalAddress : [Data]] {
        guard let messages = TestServer.allMessages[ownAddress] else {
            return [:]
        }
        TestServer.allMessages[ownAddress] = nil
        return messages
    }

    func messages(from sender: SignalAddress) -> [Data] {
        guard let mess = TestServer.allMessages[ownAddress]?[sender] else {
            return []
        }
        TestServer.allMessages[ownAddress]?[sender] = nil
        return mess
    }

    func upload(message: Data, for receiver: SignalAddress) throws {
        if TestServer.allMessages[receiver] == nil {
            TestServer.allMessages[receiver] = [SignalAddress : [Data]]()
        }
        if TestServer.allMessages[receiver]![ownAddress] == nil {
            TestServer.allMessages[receiver]![ownAddress] = [message]
        } else {
            TestServer.allMessages[receiver]![ownAddress]?.append(message)
        }
    }

    func upload(messages: [Data], for receiver: SignalAddress) throws {
        if TestServer.allMessages[receiver] == nil {
            TestServer.allMessages[receiver] = [SignalAddress : [Data]]()
        }
        if TestServer.allMessages[receiver]![ownAddress] == nil {
            TestServer.allMessages[receiver]![ownAddress] = messages
        } else {
            TestServer.allMessages[receiver]![ownAddress]!.append(contentsOf: messages)
        }
    }

    func preKeyBundle(for address: SignalAddress) throws -> PreKeyBundle {
        guard let identity = TestServer.identities[address],
            let signedKey = TestServer.signedKeys[address] else {
                throw SignalError(.invalidId, "No PreKeyBundle for \(address)")
        }
        let preKey = TestServer.prekeys[address]?.popLast()
        return PreKeyBundle(identity: identity, signedPreKey: signedKey, preKey: preKey)
    }
}
