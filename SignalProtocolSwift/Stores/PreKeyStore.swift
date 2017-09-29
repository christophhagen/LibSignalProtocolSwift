//
//  CHPreKeyStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Wrapper class to register and receive callback functions for the
 Signal Protocol Pre Key Store. This class will not directly be created
 by the user, but will be instantiated by `KeyStore`.
 */
class PreKeyStore {

    /// The delegate that receives the callbacks for the identity key store
    let delegate: PreKeyStoreDelegate

    /// The context needed to register the callbacks
    private let storeContext: OpaquePointer

    /**
     Initialize the identity key store with the context. Will be called when a
     `KeyStore` is created.

     - parameter context: The protocol store context
     - parameter delegate: The delegate that handles the calls
     */
    init?(with context: OpaquePointer, delegate: PreKeyStoreDelegate) {
        storeContext = context
        self.delegate = delegate

        var functions = signal_protocol_pre_key_store(load_pre_key: loadPreKey,
                                                       store_pre_key: storePreKey,
                                                       contains_pre_key: containsPreKey,
                                                       remove_pre_key: removePreKey,
                                                       destroy_func: cleanUp,
                                                       user_data: pointer(obj: self))
        let result = withUnsafePointer(to: &functions) { pointer in
            signal_protocol_store_context_set_pre_key_store(storeContext, pointer)
        }
        guard result == 0 else {
            return nil
        }
    }
}

/**
 Load a local serialized PreKey record.

 - parameter record: pointer to a newly allocated buffer containing the record, if found. Unset if no record was found. The Signal Protocol library is responsible for freeing this buffer.
 - parameter preKeyID: the ID of the local serialized PreKey record
 - parameter userData: A pointer to the calling instance
 - returns:  SG_SUCCESS if the key was found, SG_ERR_INVALID_KEY_ID, if the key was not found
 */
private func loadPreKey(record: UnsafeMutablePointer<UnsafeMutablePointer<signal_buffer>?>?, preKeyID: UInt32, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: PreKeyStore = instance(for: userData) else {
        return -1
    }
    guard let key = store.delegate.preKey(for: preKeyID) else {
        return SG_ERR_INVALID_KEY_ID
    }
    guard record != nil else {
        return -1
    }
    guard let pointer = signal_buffer_create(UnsafePointer(key), key.count) else {
        return SG_ERR_INVALID_KEY_ID
    }
    record!.pointee = pointer
    return 0
}

/**
 Store a local serialized PreKey record.

 - parameter id: the ID of the PreKey record to store.
 - parameter record: pointer to a buffer containing the serialized record
 - parameter length: the length of the serialized record
 - parameter caller: A pointer to the calling instance
 - returns:  0 on success, negative on failure
 */
private func storePreKey(id: UInt32, record: UnsafeMutablePointer<UInt8>?, length: Int, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: PreKeyStore = instance(for: userData) else {
        return -1
    }
    guard let pointer = record else {
        return -1
    }
    let data = Array(UnsafeMutableBufferPointer(start: pointer, count: length))
    return Int32(store.delegate.store(preKey: data, for: id) ? 0 : -1)
}

/**
 Determine whether there is a committed PreKey record matching the provided ID.

 - parameter id: A PreKey record ID.
 - parameter userData: A pointer to the calling instance
 - returns:  1 if the store has a record for the PreKey ID, 0 otherwise
 */
private func containsPreKey(id: UInt32, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: PreKeyStore = instance(for: userData) else {
        return -1
    }
    return store.delegate.containsPreKey(for: id) == true ? 1 : 0
}


/**
 Delete a PreKey record from local storage.

 - parameter id: The ID of the PreKey record to remove.
 - parameter userData: A pointer to the calling instance
 - returns:  0 on success, negative on failure
 */
private func removePreKey(id: UInt32, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: PreKeyStore = instance(for: userData) else {
        return -1
    }
    return Int32(store.delegate.removePreKey(for: id) ? 0 : -1)
}


/**
 Function called to perform cleanup when the data store context is being destroyed.
 - parameter userData: A pointer to the calling instance
 */
private func cleanUp(userData: UnsafeMutableRawPointer?) {
    let store: PreKeyStore? = instance(for: userData)
    store?.delegate.cleanUp()
}
