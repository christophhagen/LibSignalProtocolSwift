//
//  SessionStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Wrapper class to register and receive callback functions for the
 Signal Protocol Session Store. This class will not directly be created
 by the user, but will be instantiated by `KeyStore`.
 */
class SessionStore {

    /// The delegate that receives the callbacks for the identity key store
    let delegate: SessionStoreDelegate

    /// The context needed to register the callbacks
    private let storeContext: OpaquePointer

    /**
     Initialize the identity key store with the context. Will be called when a
     `KeyStore` is created.

     - parameter context: The protocol store context
     - parameter delegate: The delegate that handles the calls
     */
    init?(with context: OpaquePointer, delegate: SessionStoreDelegate) {
        storeContext = context
        self.delegate = delegate

        var functions2 = signal_protocol_session_store(load_session_func: loadSession,
                                                       get_sub_device_sessions_func: getSubDeviceSessions,
                                                       store_session_func: storeSession,
                                                       contains_session_func: containsSession,
                                                       delete_session_func: deleteSession,
                                                       delete_all_sessions_func: deleteAllSessions,
                                                       destroy_func: cleanUp,
                                                       user_data: pointer(obj: self))
        let result = withUnsafePointer(to: &functions2) { pointer in
            signal_protocol_store_context_set_session_store(storeContext, pointer)
        }
        guard result == 0 else {
            return nil
        }
    }
}

/**
 Returns a copy of the serialized session record corresponding to the provided recipient ID + device ID tuple.

 - parameter record: pointer to a freshly allocated buffer containing the serialized session record. Unset if no record was found. The Signal Protocol library is responsible for freeing this buffer.
 - parameter address: the address of the remote client
 - parameter userData: A pointer to the calling instance
 - returns: 1 if the session was loaded, 0 if the session was not found, negative on failure
 */
private func loadSession(record: UnsafeMutablePointer<UnsafeMutablePointer<signal_buffer>?>?,
                          address: UnsafePointer<signal_protocol_address>?, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: SessionStore = instance(for: userData) else {
        return -1
    }
    guard record != nil else {
        return -1
    }
    guard let convertedAddress = CHAddress(from: address) else {
        return -1
    }
    guard let session = store.delegate.loadSession(for: convertedAddress) else {
        return 0
    }
    guard let buffer = signal_buffer_create(UnsafePointer(session), session.count) else {
        return SG_ERR_NOMEM
    }
    record!.pointee = buffer
    return 1
}

/**
 Returns all known devices with active sessions for a recipient

 - parameter sessions: pointer to an array that will be allocated and populated with the result
 - parameter name: the name of the remote client
 - parameter length: the length of the name
 - parameter userData: A pointer to the calling instance
 - returns: size of the sessions array, or negative on failure
 */
private func getSubDeviceSessions(sessions: UnsafeMutablePointer<OpaquePointer?>?,
                                   name: UnsafePointer<Int8>?,
                                   length: Int,
                                   userData: UnsafeMutableRawPointer?) -> Int32 {

    guard let store: SessionStore = instance(for: userData) else {
        return -1
    }
    guard sessions != nil else {
        return -1
    }
    guard let nameString = stringFromBuffer(name, length: length) else {
        return -1
    }
    let list = store.delegate.subDeviceSessions(for: nameString)

    guard let listPointer = signal_int_list_alloc() else {
        return SG_ERR_NOMEM
    }
    for item in list {
        signal_int_list_push_back(listPointer, item)
    }
    sessions!.pointee = listPointer
    return Int32(list.count)
}

/**
 Commit to storage the session record for a given recipient ID + device ID tuple.

 - parameter address: the address of the remote client
 - parameter data: pointer to a buffer containing the serialized session record for the remote client
 - parameter length: length of the serialized session record
 - parameter userData: A pointer to the calling instance
 - returns: 0 on success, negative on failure
 */
private func storeSession(address: UnsafePointer<signal_protocol_address>?, data: UnsafeMutablePointer<UInt8>?, length: Int, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let convertedAddress = CHAddress(from: address), let recordPointer = data else {
        return -1
    }
    let record = Array(UnsafeMutableBufferPointer(start: recordPointer, count: length))
    guard let store: SessionStore = instance(for: userData) else {
        return -1
    }
    return Int32(store.delegate.store(session: record, for: convertedAddress) ? 0 : -1)
}


/**
 Determine whether there is a committed session record for a recipient ID + device ID tuple.

 - parameter address: the address of the remote client
 - parameter userData: A pointer to the calling instance
 - returns: 1 if a session record exists, 0 otherwise.
 */
private func containsSession(address: UnsafePointer<signal_protocol_address>?, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let convertedAddress = CHAddress(from: address) else {
        return -1
    }
    guard let store: SessionStore = instance(for: userData) else {
        return -1
    }
    return store.delegate.containsSession(for: convertedAddress) ? 1 : 0
}


/**
 Remove a session record for a recipient ID + device ID tuple.

 - parameter address: the address of the remote client
 - parameter userData: A pointer to the calling instance
 - returns: 1 if a session was deleted, 0 if a session was not deleted, negative on error
 */
private func deleteSession(address: UnsafePointer<signal_protocol_address>?, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: SessionStore = instance(for: userData) else {
        return -1
    }
    guard let convertedAddress = CHAddress(from: address) else {
        return -1
    }
    return store.delegate.deleteSession(for: convertedAddress) ? 1 : 0
}


/**
 Remove the session records corresponding to all devices of a recipient ID.

 -parameter name: the name of the remote client
 -parameter length: the length of the name
 -parameter userData: A pointer to the calling instance
 - returns: the number of deleted sessions on success, negative on failure
 */
private func deleteAllSessions(name: UnsafePointer<Int8>?, length: Int, userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: SessionStore = instance(for: userData) else {
        return -1
    }
    guard let nameString = stringFromBuffer(name, length: length) else {
        return -1
    }
    return Int32(store.delegate.deleteAllSessions(for: nameString))
}

/**
 Function called to perform cleanup when the data store context is being destroyed.

 - parameter userData: A pointer to the calling instance
 */
private func cleanUp(userData: UnsafeMutableRawPointer?) {
    let store: SessionStore? = instance(for: userData)
    store?.delegate.cleanUp()
}
