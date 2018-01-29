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
 unspecified data blobs. 
 */
public protocol SenderKeyStoreDelegate {

    associatedtype Address: Hashable

    /**
     Returns a copy of the sender key record corresponding to the address tuple.

     - parameter senderKeyName: The address and group of the remote client
     - returns: The Sender Key, if it exists, or nil
     */
    func senderKey(for address: Address) -> Data?

    /**
     Stores a copy of the sender key record corresponding to the (groupId + senderId + deviceId) tuple.

     - parameter senderKey: The key to store
     - parameter senderKeyName: The address and group of the remote client
     - throws: `SignalError` of type `storageError`, if the record could not be stored
     */
    func store(senderKey: Data, for address: Address) throws

}

extension SenderKeyStoreDelegate {
    /**
     Returns a copy of the sender key record corresponding to the address.

     - parameter senderKeyName: The address and group of the remote client
     - returns: The Sender Key, or nil if no key exists
     - throws: `SignalError` of type `invalidProtoBuf`, if the record is corrupt
     */
    func senderKey(for address: Address) throws -> SenderKeyRecord? {
        guard let senderKey = senderKey(for: address) else {
            return nil
        }
        return try SenderKeyRecord(from: senderKey)
    }

    /**
     Stores a copy of the sender key record corresponding to the address tuple.

     - parameter senderKey: The key to store
     - parameter senderKeyName: The address and group of the remote client
     - throws: `SignalErrorType.storageError`, `SignalErrorType.invalidProtoBuf`
     */
    func store(senderKey: SenderKeyRecord, for address: Address) throws {
        let data = try senderKey.data()
        try store(senderKey: data, for: address)
    }
}
