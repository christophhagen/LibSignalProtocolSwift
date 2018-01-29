//
//  TestSenderKeyStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import SignalProtocolSwift

/**
 Implement the `SenderKeyStore` protocol to handle the sender key storage of the Signal Protocol.
 */
class TestSenderKeyStore: SenderKeyStore {

    /// The type that distinguishes different groups and devices/users
    typealias Address = SignalSenderKeyName

    private var senderKeys = [SignalSenderKeyName : Data]()

    /**
     Returns a copy of the sender key record corresponding to the address tuple.
     - parameter address: The group address of the remote client
     - returns: The Sender Key, if it exists, or nil
     */
    func senderKey(for address: SignalSenderKeyName) -> Data? {
        return senderKeys[address]
    }

    /**
     Stores the sender key record.
     - parameter senderKey: The key to store
     - parameter address: The group address of the remote client
     */
    func store(senderKey: Data, for address: SignalSenderKeyName) throws {
        senderKeys[address] = senderKey
    }
}
