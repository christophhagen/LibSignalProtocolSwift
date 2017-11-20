//
//  GroupSessionBuilder.swift
//  libsignal-protocol-swift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation



public struct GroupSessionBuilder {

    var store: SignalProtocolStoreContext

    public init(store: SignalProtocolStoreContext) {
        self.store = store
    }

    public func processSession(
        senderKeyName: SignalSenderKeyName,
        distributionMessageData message: CipherTextMessage) throws {
        guard message.type == .senderKeyDistribution else {
            throw SignalError(.invalidType, "Invalid message type \(message.type)")
        }
        let object = try SenderKeyDistributionMessage(from: message.data)
        try processSession(senderKeyName: senderKeyName,
                           distributionMessage: object)
    }

    public func processSession(
        senderKeyName: SignalSenderKeyName,
        distributionMessage: SenderKeyDistributionMessage) throws {

        let senderKey = try store.loadSenderKey(for: senderKeyName) ?? SenderKeyRecord()

        senderKey.addState(
            id: distributionMessage.id,
            iteration: distributionMessage.iteration,
            chainKey: distributionMessage.chainKey,
            signaturePublicKey: distributionMessage.signatureKey,
            signaturePrivateKey: nil)

        try store.store(senderKey: senderKey, for: senderKeyName)
    }

    public func createSession(senderKeyName: SignalSenderKeyName) throws -> SenderKeyDistributionMessage {

        let record = try store.loadSenderKey(for: senderKeyName) ?? SenderKeyRecord()

        if record.isEmpty {
            let senderKeyId = try SignalCrypto.generateSenderKeyId()
            let senderKey = try SignalCrypto.generateSenderKey()
            let senderSigningKey = try SignalCrypto.generateSenderSigningKey()
            record.setSenderKey(id: senderKeyId,
                                iteration: 0,
                                chainKey: senderKey,
                                signatureKeyPair: senderSigningKey)
            try store.store(senderKey: record, for: senderKeyName)
        }

        guard let state = record.state else {
            throw SignalError(.unknown, "No state in record")
        }

        let chainKey = state.chainKey
        let seed = chainKey.chainKey

        return SenderKeyDistributionMessage(
            id: state.keyId,
            iteration: chainKey.iteration,
            chainKey: seed,
            signatureKey: state.signaturePublicKey)

    }
}
