//
//  SenderKeyStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `SenderKeyStoreDelegate` protocol to handle the Sender Key storage of the
 Signal Protocol API. The keys should be stored in a secure database and be treated as
 unspecified data blobs. Register your implementation with an instance of `KeyStore` to
 receive events.
 */
protocol SenderKeyStoreDelegate {

    /**
     Returns a copy of the sender key record corresponding to the (groupId + senderId + deviceId) tuple.

     - parameter address: The address of the remote client
     - parameter groupID: The group associated with the key
     - returns: The Sender Key, if it exists, or nil
     */
    func loadSenderKey(for address: CHAddress, and groupID: String) -> [UInt8]?

    /**
     Stores a copy of the sender key record corresponding to the (groupId + senderId + deviceId) tuple.

     - parameter senderKey: The key to store
     - parameter address: The address of the remote client
     - parameter groupID: The group associated with the key
     - returns: `true` if the key was stored
     */
    func store(senderKey: [UInt8], for address: CHAddress, and groupID: String) -> Bool

    /**
     Function called to perform cleanup when the data store context is being destroyed.
     */
    func cleanUp()
}
