//
//  TestSignedPreKeyStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import SignalProtocolSwift

/**
 Implement the `SignedPreKeyStore` protocol to handle the signed pre key storage of the Signal Protocol.
 */
class TestSignedPreKeyStore: SignedPreKeyStore {

    /// Dictionary of the signed pre keys
    private var signedKeys = [UInt32 : Data]()

    /// The id of the last SignedPreKey that was stored.
    var lastId: UInt32 = 0

    /**
     Provide a Signed Pre Key for a given id.
     - parameter id: The Signed Pre Key Id
     - returns: The Signed Pre Key
     - throws: `SignalError` of type `invalidId` if no key exists for the id
     */
    func signedPreKey(for id: UInt32) throws -> Data {
        guard let key = signedKeys[id] else {
            throw SignalError(.invalidId, "No signed pre key for id \(id)")
        }
        return key
    }

    /**
     Store a Signed Pre Key for a given id.
     - parameter signedPreKey: The Signed Pre Key to store
     - parameter id: The Signed Pre Key id
     - throws: `SignalError` of type `storageError`, if the key could not be stored
     */
    func store(signedPreKey: Data, for id: UInt32) throws {
        signedKeys[id] = signedPreKey
        lastId = id
    }

    /**
     Indicate if a Signed Pre Key exists for an id.
     - parameter id: The Signed Pre Key id
     - returns: `true` if a key exists
     - throws: `SignalError` of type `storageError`, if the key could not be accessed
     */
    func containsSignedPreKey(for id: UInt32) -> Bool {
        return signedKeys[id] != nil
    }

    /**
     Remove a Signed Pre Key.
     - parameter id: The Signed Pre Key id.
     - throws: `SignalError`of type `invalidId`
     */
    func removeSignedPreKey(for id: UInt32) throws {
        signedKeys[id] = nil
    }

    /**
     Get all Ids for the SignedPreKeys in the store.
     - returns: An array of all ids for which a key is stored
     - throws: `SignalError` of type `storageError`, if the key could not be accessed
     */
    func allIds() -> [UInt32] {
        return [UInt32](signedKeys.keys)
    }

}
