//
//  SenderKeyRecord.swift
//  libsignal-protocol-swift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Stores the states for a session.
 */
final class SenderKeyRecord {

    /// The maximum number of different states that are saved
    private static let maxStates = 5

    /// The states that are saved by the record, sorted by most recent
    private var states = [SenderKeyState]()

    /// The active state is the most recent, if any states exist
    var state: SenderKeyState? {
        return states.first
    }

    /// Indicate if there are any states in this record
    var isEmpty: Bool {
        return states.count == 0
    }

    /**
     Create a fresh session record without any states.
    */
    init() {
        // Nothing to do here
    }

    /**
     Get the state for an id.
     - parameter id: The key id of the requested state
     - returns: The state for the id, if present
    */
    func state(for id: UInt32) -> SenderKeyState? {
        for item in states {
            if item.keyId == id {
                return state
            }
        }
        return nil
    }

    /**
     Set a new sender key state and delete all previous states.
     - parameter id: The state id
     - parameter iteration: The state iteration
     - parameter chainKey: The serialized chain key for the state
     - parameter signatureKeyPair: The key for the state.
    */
    func setSenderKey(
        id: UInt32,
        iteration: UInt32,
        chainKey: Data,
        signatureKeyPair: KeyPair) {

        self.states = []
        addState(
            id: id,
            iteration: iteration,
            chainKey: chainKey,
            signatureKeyPair: signatureKeyPair)
    }

    /**
     Add a new sender key state.
     - note: Deletes old states if the maximum number is reached.
     - parameter id: The state id
     - parameter iteration: The state iteration
     - parameter chainKey: The serialized chain key for the state
     - parameter signaturePublicKey: The public key for the state.
     - parameter signaturePrivateKey: The private key for the state.
     */
    func addState(
        id: UInt32,
        iteration: UInt32,
        chainKey: Data,
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

    /**
     Add a new sender key state.
     - note: Deletes old states if the maximum number is reached.
     - parameter id: The state id
     - parameter iteration: The state iteration
     - parameter chainKey: The serialized chain key for the state
     - parameter signatureKeyPair: The key for the state.
     */
    func addState(id: UInt32,
                  iteration: UInt32,
                  chainKey: Data,
                  signatureKeyPair: KeyPair) {
        addState(id: id,
                 iteration: iteration,
                 chainKey: chainKey,
                 signaturePublicKey: signatureKeyPair.publicKey,
                 signaturePrivateKey: signatureKeyPair.privateKey)
    }
    
    // MARK: Protocol Buffers

    /// The record converted to a ProtoBuf object for storage
    var object: Textsecure_SenderKeyRecordStructure {
        return Textsecure_SenderKeyRecordStructure.with {
            $0.senderKeyStates = self.states.map { $0.object }
        }
    }

    /**
     The record converted to data for storage
     - returns: The serialized record.
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SenderKeyRecord: \(error)")
        }
    }

    /**
     Create a record from a ProtoBuf object.
     - note: This init takes data produced by calls to `object`
     - parameter object: The ProtoBuf object
     - throws: `SignalError` `invalidProtoBuf` if the object is corrupted.
    */
    init(from object: Textsecure_SenderKeyRecordStructure) throws {
        self.states = try object.senderKeyStates.map { try SenderKeyState(from: $0) }
    }

    /**
     Create a record from serialized data.
     - note: This init takes data produced by calls to `data()`
     - parameter data: The data
     - throws: `SignalError` `invalidProtoBuf` if the data is corrupted.
     */
    convenience init(from data: Data) throws {
        let object: Textsecure_SenderKeyRecordStructure
        do {
            object = try Textsecure_SenderKeyRecordStructure(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create SenderKeyRecord object: \(error)")
        }
        try self.init(from: object)
    }
}

extension SenderKeyRecord: Equatable {
    /**
     Compare two records.
     - note: Two record are equal, if all their states are equal, and in the correct order.
     - parameter lhs: The first record.
     - parameter rhs: The second record.
     - returns: `True` if the records match.
    */
    static func ==(lhs: SenderKeyRecord, rhs: SenderKeyRecord) -> Bool {
        return lhs.states == rhs.states
    }
}
