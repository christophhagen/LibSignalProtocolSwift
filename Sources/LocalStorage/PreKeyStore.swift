//
//  PreKeyStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `PreKeyStore` protocol to handle the pre key storage of the
 Signal Protocol. The keys should be stored in a secure database and be treated as
 unspecified data blobs. 
 */
public protocol PreKeyStore: class {

    /**
     Provide a Pre Key for a given id.

     - parameter id: The pre key ID
     - returns: The pre key
     - throws: `SignalError` of type `invalidId`, if no key exists
     */
    func preKey(for id: UInt32) throws -> Data

    /**
     Store a pre key for a given id.
     - parameter preKey: The key to store
     - parameter id: The pre key id
     - throws: `SignalError` of type `storageError`, if the key can't be saved
     */
    func store(preKey: Data, for id: UInt32) throws

    /**
     Indicate if a pre key exists for an id.
     - parameter id: The pre key id
     - returns: `true` if a key exists
     */
    func containsPreKey(for id: UInt32) -> Bool

    /**
     Remove a pre key.
     - parameter id: The pre key id.
     - returns: `true` if the key was removed
     - throws: `SignalError` of type `storageError`, if the key can't be removed
     */
    func removePreKey(for id: UInt32) throws

    /// Return the id of the last stored pre key.
    var lastId: UInt32 { get set }
    
}

extension PreKeyStore {

    /**
     Provide a Pre Key for a given id.
     - note: Possible errors:
     - `invalidId`, if no key exists
     - `invalidProtoBuf`, if data is corrupt or missing
     - parameter id: The pre key id
     - returns: The pre key
     - throws: `SignalError`
     */
    func preKey(for id: UInt32) throws -> SessionPreKey {
        let data = try preKey(for: id)
        return try SessionPreKey(from: data)
    }

    /**
     Store a pre key for a given id.
     - note: Possible errors:
     - `storageError`, if no key exists
     - `invalidProtoBuf`, if the key could not be serialized
     - parameter preKey: The key to store
     - throws: `SignalError`
     */
    func store(preKey: SessionPreKey) throws {
        let data = try preKey.protoData()
        try store(preKey: data, for: preKey.publicKey.id)
    }
}
