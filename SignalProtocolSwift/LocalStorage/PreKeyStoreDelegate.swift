//
//  PreKeyStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `PreKeyStoreDelegate` protocol to handle the Pre Key storage of the
 Signal Protocol API. The keys should be stored in a secure database and be treated as
 unspecified data blobs. Register your implementation with an instance of `KeyStore` to
 receive events.
 */
protocol PreKeyStoreDelegate {

    /**
     Provide a Pre Key for a given id.

     - parameter id: The pre key ID
     - returns: The pre key, or `nil` if no key exists
     */
    func preKey(for id: UInt32) -> Data?

    /**
     Store a pre key for a given id.

     - parameter preKey: The key to store
     - parameter id: The pre key id
     - returns: `true` if the key was stored
     */
    func store(preKey: Data, for id: UInt32) -> Bool

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
     */
    func removePreKey(for id: UInt32) -> Bool
    
}
