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
public protocol SenderKeyStoreDelegate {

    /**
     Returns a copy of the sender key record corresponding to the (groupId + senderId + deviceId) tuple.

     - parameter senderKeyName: The address and group of the remote client
     - returns: The Sender Key, if it exists, or nil
     */
    func loadSenderKey(senderKeyName: SignalSenderKeyName) -> Data?

    /**
     Stores a copy of the sender key record corresponding to the (groupId + senderId + deviceId) tuple.

     - parameter senderKey: The key to store
     - parameter senderKeyName: The address and group of the remote client
     - returns: `true` if the key was stored
     */
    func store(senderKey: Data, for senderKeyName: SignalSenderKeyName) -> Bool

}
