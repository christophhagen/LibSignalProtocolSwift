//
//  SignedPreKeyStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Wrapper class to register and receive callback functions for the
 Signal Protocol Signed Pre Key Store. This class will not directly be created
 by the user, but will be instantiated by `KeyStore`.
 */
class SignedPreKeyStore {

    /// The delegate that receives the callbacks for the identity key store
    let delegate: SignedPreKeyStoreDelegate

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
    init?(with context: OpaquePointer, delegate: SignedPreKeyStoreDelegate) {
        storeContext = context
        self.delegate = delegate

        var functions = signal_protocol_signed_pre_key_store(load_signed_pre_key: loadSignedPreKey,
                                                             store_signed_pre_key: storeSignedPreKey,
                                                             contains_signed_pre_key: containsSignedPreKey,
                                                             remove_signed_pre_key: removeSignedPreKey,
                                                             destroy_func: cleanup,
                                                             user_data: pointer(obj: self))
        let result = withUnsafePointer(to: &functions) { pointer in
            signal_protocol_store_context_set_signed_pre_key_store(storeContext, pointer)
        }
        guard result == 0 else {
            return nil
        }
    }
}

/** Load a local serialized signed PreKey record.

 - parameter record: pointer to a newly allocated buffer containing the record, if found. Unset if no record was found. The Signal Protocol library is responsible for freeing this buffer.
 - parameter signedPreKeyID: the ID of the local signed PreKey record
 - parameter userData: A pointer to the calling instance
 - returns: SG_SUCCESS if the key was found, SG_ERR_INVALID_KEY_ID if the key could not be found
 */
private func loadSignedPreKey(record: UnsafeMutablePointer<UnsafeMutablePointer<signal_buffer>?>?,
                               signedPreKeyID: UInt32,
                               userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: SignedPreKeyStore = instance(for: userData) else {
        return -1
    }
    guard record != nil else {
        return -1
    }
    guard let key = store.delegate.signedPreKey(for: signedPreKeyID) else {
        return SG_ERR_INVALID_KEY_ID
    }
    guard let buffer = signal_buffer_create(UnsafePointer(key), key.count) else {
        return SG_ERR_NOMEM
    }
    record!.pointee = buffer
    return SG_SUCCESS
}

/** Store a local serialized signed PreKey record.

 - parameter id: the ID of the signed PreKey record to store
 - parameter record: pointer to a buffer containing the serialized record
 - parameter length: length of the serialized record
 - parameter caller: A pointer to the calling instance
 - returns: 0 on success, negative on failure
 */
private func storeSignedPreKey(id: UInt32, record: UnsafeMutablePointer<UInt8>?, length: Int, caller: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: SignedPreKeyStore = instance(for: caller) else {
        return -1
    }
    guard let pointer = record else {
        return -1
    }
    let data = Array(UnsafeMutableBufferPointer(start: pointer, count: length))
    return Int32(store.delegate.store(signedPreKey: data, for: id) ? 0 : -1)
}


/** Determine whether there is a committed signed PreKey record matching the provided ID.

 - parameter id: A signed PreKey record ID.
 - parameter caller: A pointer to the calling instance
 - returns: 1 if the store has a record for the signed PreKey ID, 0 otherwise
 */
private func containsSignedPreKey(id: UInt32, caller: UnsafeMutableRawPointer?) -> Int32 {
    let store: SignedPreKeyStore? = instance(for: caller)
    return store?.delegate.containsSignedPreKey(for: id) == true ? 1 : 0
}


/** Delete a SignedPreKeyRecord from local storage.

 - parameter id: The ID of the signed PreKey record to remove.
 - parameter caller: A pointer to the calling instance
 - returns: 0 on success, negative on failure
 */
private func removeSignedPreKey(id: UInt32, caller: UnsafeMutableRawPointer?) -> Int32 {
    let store: SignedPreKeyStore? = instance(for: caller)
    return Int32(store?.delegate.removeSignedPreKey(for: id) ?? false ? 0 : -1)
}


/** Function called to perform cleanup when the data store context is being destroyed.
 - parameter caller: A pointer to the calling instance
 */
private func cleanup(caller: UnsafeMutableRawPointer?){
    let store: PreKeyStore? = instance(for: caller)
    store?.delegate.cleanUp()
}
