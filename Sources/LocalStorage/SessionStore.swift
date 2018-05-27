//
//  SessionStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `SessionStore` protocol to handle the session records of the
 Signal Protocol. The records should be stored in a secure database and be treated as
 unspecified data blobs. 
 */
public protocol SessionStore: class {

    /// The type that distinguishes different devices/users
    associatedtype Address: Hashable

    /**
     Load a session for a given address.
     - parameter address: The address of the remote client
     - returns: The session record, or nil if no record exists
     - throws: `SignalError` of type `storageError`
     */
    func loadSession(for address: Address) throws -> Data?

    /**
     Store a session record for a remote client.
     - parameter session: The session record to store
     - parameter address: The address of the remote client
     - returns: `true` on success, `false` on error
     - throws: `SignalError` of type `storageError`
     */
    func store(session: Data, for address: Address) throws

    /**
     Indicate if a record exists for the client address
     - parameter address: The address of the remote client
     - returns: `true` if a record exists
     */
    func containsSession(for address: Address) -> Bool

    /**
     Delete a session for a remote client.
     - parameter address: The address of the remote client
     - returns: `true` if the session was deleted
     - throws: `SignalError` of type `storageError`
     */
    func deleteSession(for address: Address) throws
}

extension SessionStore {

    /**
     Load a session for a given address.
     - parameter address: The address of the remote client
     - returns: The loaded session record, or a new one if no session exists for the address
     - throws: `SignalError` of type `storageError` for an invalid record
     */
    func loadSession(for address: Address) throws -> SessionRecord {
        guard let record = try loadSession(for: address) else {
            return SessionRecord(state: nil)
        }
        return try SessionRecord(from: record)
    }

    /**
     Store a session record for a remote client.
     - note: Possible errors:
     - ` storageError`, if the session record could not be stored
     - `invalidProtoBuf`, if the session record could not be serialized
     - parameter session: The session record to store
     - parameter address: The address of the remote client
     - throws: `SignalError` errors
     */
    func store(session: SessionRecord, for address: Address) throws {
        let data = try session.protoData()
        try store(session: data, for: address)
    }
}
