//
//  SignedPrekeyStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `SignedPreKeyStoreDelegate` protocol to handle the Signed Pre Key storage of the
 Signal Protocol API. The keys should be stored in a secure database and be treated as
 unspecified data blobs. Register your implementation with an instance of `KeyStore` to
 receive events.
 */
public protocol SignedPreKeyStoreDelegate {

    /**
     Provide a Signed Pre Key for a given id.
     - parameter id: The Signed Pre Key Id
     - returns: The Signed Pre Key
     - throws: `SignalError` of type `invalidId` if no key exists for the id
     */
    func signedPreKey(for id: UInt32) throws -> Data

    /**
     Store a Signed Pre Key for a given id.
     - parameter signedPreKey: The Signed Pre Key to store
     - parameter id: The Signed Pre Key id
     - throws: `SignalError` of type `storageError`, if the key could not be stored
     */
    func store(signedPreKey: Data, for id: UInt32) throws

    /**
     Indicate if a Signed Pre Key exists for an id.
     - parameter id: The Signed Pre Key id
     - returns: `true` if a key exists
     */
    func containsSignedPreKey(for id: UInt32) -> Bool

    /**
     Remove a Signed Pre Key.
     - parameter id: The Signed Pre Key id.
     - throws: `SignalError`of type `invalidId`
     */
    func removeSignedPreKey(for id: UInt32) throws

    /**
     Get all Ids for the SignedPreKeys in the store.
     - returns: An array of all ids for which a key is stored
    */
    func allIds() -> [UInt32]

    /**
     The id of the last SignedPreKey that was stored.
    */
    var lastId: UInt32 { get }
}

extension SignedPreKeyStoreDelegate {

    /**
     Provide a Signed Pre Key for a given id.
     - note: Possible errors:
     - `invalidId`, if no pre key exists for the id
     - `invalidProtobuf`, if the key data is corrupt
     - parameter id: The Signed Pre Key ID
     - returns: The Signed Pre Key
     - throws: `SignalError` errors
     */
    public func signedPreKey(for id: UInt32) throws -> SessionSignedPreKey {
        let record = try signedPreKey(for: id)
        return try SessionSignedPreKey(from: record)
    }

    /**
     Store a Signed Pre Key for a given id.
     - note: Possible errors:
     - `invalidProtobuf`, if the key could not be serialized
     - `storageError`, if the key could not be stored
     - parameter signedPreKey: The Signed Pre Key to store
     - throws: `SignalError` errors
     */
    public func store(signedPreKey: SessionSignedPreKey) throws {
        let data = try signedPreKey.data()
        try store(signedPreKey: data, for: signedPreKey.id)
    }
}
