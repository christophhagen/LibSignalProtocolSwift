//
//  ProtocolWrapper.swift
//  TestC
//
//  Created by User on 17.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Wrapper class to register and receive callback functions for the
 Signal Sender Key Store. This class will not directly be created
 by the user, but will be instantiated by `KeyStore`.
 */
class SenderKeyStore {

    /// The delegate that receives the callbacks for the sender key store
    let delegate: SenderKeyStoreDelegate

    /// Private variable to retain data until the callbacks have copied it
    private var retainedData = [UInt8]()

    /// The context needed to register the callbacks
    private let storeContext: OpaquePointer

    /**
     Initialize the identity key store with the context. Will be called when a
     `KeyStore` is created.

     - parameter context: The protocol store context
     - parameter delegate: The delegate that handles the calls
     */
    init?(with context: OpaquePointer, delegate: SenderKeyStoreDelegate) {
        storeContext = context
        self.delegate = delegate

        var functions2 = signal_protocol_sender_key_store(store_sender_key: storeSenderKey,
                                                         load_sender_key: loadSenderKey,
                                                         destroy_func: cleanup,
                                                         user_data: pointer(obj: self))
        let result = withUnsafePointer(to: &functions2) { pointer in
            signal_protocol_store_context_set_sender_key_store(storeContext, pointer)
        }
        guard result == 0 else {
            return nil
        }
    }
}

/**
 Internal function to convert a pointer to a sender key name into an address and a name.

 - parameter senderKey: The pointer to the tuple (groupId + senderId + deviceId)
 - returns: The address and the name, or nil on error
 */
private func unpack(senderID: UnsafePointer<signal_protocol_sender_key_name>?) -> (CHAddress, String)? {
    guard let namePointer = senderID?.pointee else {
        return nil
    }
    guard let nameString = stringFromBuffer(namePointer.group_id, length: namePointer.group_id_len) else {
        return nil
    }
    guard let address = CHAddress(address: namePointer.sender) else {
        return nil
    }
    return (address, nameString)
}

/**
 * Returns a copy of the sender key record corresponding to the
 * (groupId + senderId + deviceId) tuple.
 *
 * @param record pointer to a newly allocated buffer containing the record,
 *     if found. Unset if no record was found.
 *     The Signal Protocol library is responsible for freeing this buffer.
 * @param sender_key_name the (groupId + senderId + deviceId) tuple
 * @param user_data A pointer to user data, unused here
 * @return 1 if the record was loaded, 0 if the record was not found, negative on failure
 */
private func loadSenderKey(record: UnsafeMutablePointer<UnsafeMutablePointer<signal_buffer>?>?,
                            senderKeyName: UnsafePointer<signal_protocol_sender_key_name>?,
                            userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: SenderKeyStore = instance(for: userData) else {
        return -1
    }
    guard record != nil else {
        return -1
    }
    guard let (address, name) = unpack(senderID: senderKeyName) else {
        return -1
    }
    guard let key = store.delegate.loadSenderKey(for: address, and: name) else {
        return 0
    }
    guard let buffer = signal_buffer_create(UnsafePointer(key), key.count) else {
        return -1
    }
    record!.pointee = buffer
    return 1
}

/**
 Store a serialized sender key record for a given (groupId + senderId + deviceId) tuple.

 - parameter name: the (groupId + senderId + deviceId) tuple
 - parameter record: pointer to a buffer containing the serialized record
 - parameter length: the length of the serialized record
 - parameter userData: A pointer to user data, unused here
 - returns: 0 on success, negative on failure
 */
private func storeSenderKey(name: UnsafePointer<signal_protocol_sender_key_name>?, record: UnsafeMutablePointer<UInt8>?, length: Int, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: SenderKeyStore = instance(for: userData) else {
        return -1
    }
    guard let (address, groupID) = unpack(senderID: name), let pointer = record else {
        return -1
    }
    let data = Array(UnsafeMutableBufferPointer(start: pointer, count: length))
    return store.delegate.store(senderKey: data, for: address, and: groupID) ? 0 : -1
}

/**
 Function called to perform cleanup when the data store context is being destroyed.

 - parameter caller: A pointer to user data, unused here
 */
private func cleanup(userData: UnsafeMutableRawPointer?) {
    guard let store: SenderKeyStore = instance(for: userData) else {
        return
    }
    store.delegate.cleanUp()
}
