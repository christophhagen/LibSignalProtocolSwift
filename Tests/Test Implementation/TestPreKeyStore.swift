//
//  TestPreKeyStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import Foundation
import SignalProtocol

/**
 Implement the `PreKeyStore` protocol to handle the pre key storage of the Signal Protocol.
 */
class TestPreKeyStore: PreKeyStore {

    /// Return the id of the last stored pre key.
    var lastId: UInt32 = 0

    /// Dictionary of the pre keys by id
    private var preKeys = [UInt32 : Data]()

    /**
     Provide a Pre Key for a given id.
     - parameter id: The pre key ID
     - returns: The pre key
     */
    func preKey(for id: UInt32) throws -> Data {
        guard let key = preKeys[id] else {
            throw SignalError(.storageError, "No pre key for id \(id)")
        }
        return key
    }

    /**
     Store a pre key for a given id.
     - parameter preKey: The key to store
     - parameter id: The pre key id
     */
    func store(preKey: Data, for id: UInt32) throws {
        preKeys[id] = preKey
        lastId = id
    }

    /**
     Indicate if a pre key exists for an id.
     - parameter id: The pre key id
     - returns: `true` if a key exists
     */
    func containsPreKey(for id: UInt32) -> Bool {
        return preKeys[id] != nil
    }

    /**
     Remove a pre key.
     - parameter id: The pre key id.
     - returns: `true` if the key was removed
     */
    func removePreKey(for id: UInt32) throws {
        preKeys[id] = nil
    }

}
