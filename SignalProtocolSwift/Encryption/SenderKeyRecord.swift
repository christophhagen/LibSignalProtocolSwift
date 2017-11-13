//
//  SenderKeyRecord.swift
//  libsignal-protocol-swift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

final class SenderKeyRecord {

    static let maxStates = 5

    var states: [SenderKeyState]

    init() {
        self.states = [SenderKeyState]()
    }

    var state: SenderKeyState? {
        if let output = states.first {
            return output
        } else {
            signalLog(level: .error, "No key state in record")
            return nil
        }

    }

    var isEmpty: Bool {
        return states.count == 0
    }

    func state(for id: UInt32) -> SenderKeyState? {
        for item in states {
            if item.keyId == id {
                return state
            }
        }
        signalLog(level: .error, "No keys for \(id)")
        return nil
    }

    func setSenderKey(
        id: UInt32,
        iteration: UInt32,
        chainKey: [UInt8],
        signatureKeyPair: KeyPair) {

        self.states = []
        addState(
            id: id,
            iteration: iteration,
            chainKey: chainKey,
            signatureKeyPair: signatureKeyPair)
    }

    func addState(
        id: UInt32,
        iteration: UInt32,
        chainKey: [UInt8],
        signaturePublicKey: PublicKey,
        signaturePrivateKey: PrivateKey?) {

        let chainKeyElement = SenderChainKey(
            iteration: iteration,
            chainKey: chainKey)

        let state = SenderKeyState(
            keyId: id,
            chainKey: chainKeyElement,
            signaturePublicKey: signaturePublicKey,
            signaturePrivateKey: signaturePrivateKey)

        states.insert(state, at: 0)

        if states.count > SenderKeyRecord.maxStates {
            states = Array(states[0..<SenderKeyRecord.maxStates])
        }
    }

    func addState(id: UInt32,
                  iteration: UInt32,
                  chainKey: [UInt8],
                  signatureKeyPair: KeyPair) {
        addState(id: id,
                 iteration: iteration,
                 chainKey: chainKey,
                 signaturePublicKey: signatureKeyPair.publicKey,
                 signaturePrivateKey: signatureKeyPair.privateKey)
    }
    
    // MARK: Protocol Buffers

    func object() throws -> Textsecure_SenderKeyRecordStructure {
        return try Textsecure_SenderKeyRecordStructure.with {
            $0.senderKeyStates = try self.states.map { try $0.object() }
        }
    }
    
    func data() throws -> Data {
        return try object().serializedData()
    }

    init(from object: Textsecure_SenderKeyRecordStructure) throws {
        self.states = try object.senderKeyStates.map { try SenderKeyState(from: $0) }
    }
    
    convenience init(from data: Data) throws {
        let object = try Textsecure_SenderKeyRecordStructure(serializedData: data)
        try self.init(from: object)
    }
}

extension SenderKeyRecord: Equatable {
    static func ==(lhs: SenderKeyRecord, rhs: SenderKeyRecord) -> Bool {
        return lhs.states == rhs.states
    }
}
