//
//  SessionStoreDelegate.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Implement the `SessionStoreDelegate` protocol to handle the Session records of the
 Signal Protocol API. The records should be stored in a secure database and be treated as
 unspecified data blobs. 
 */
public protocol SessionStoreDelegate {

    /// The address of a user or device
    associatedtype Address: Hashable

    /**
     Load a session for a given address.

     - parameter address: The address of the remote client
     - returns: The session record, or nil if no record exists
     */
    func loadSession(for address: Address) -> Data?

    /**
     Retreive the recipient IDs of all active sessions for a remote client.

     - parameter recipientID: The name of the remote client.
     - returns: An array of recipient IDs
     */
    func subDeviceSessions(for recipientID: String) -> [UInt32]

    /**
     Store a session record for a remote client.

     - parameter session: The session record to store
     - parameter address: The address of the remote client
     - returns: `true` on success, `false` on error
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
     */
    func deleteSession(for address: Address) throws

    /**
     Delete all session records for a given client.

     - parameter recipientID: The name of the remote client
     - returns: The number of deleted records
     */
    func deleteAllSessions(for recipientID: String) -> Int

}

extension SessionStoreDelegate {

    /**
     Load a session for a given address.
     - parameter address: The address of the remote client
     - returns: The loaded session record, or a new one if no session exists for the address
     - throws: `SignalError` of type `storageError` for an invalid record
     */
    func loadSession(for address: Address) throws -> SessionRecord {
        guard let record = loadSession(for: address) else {
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
        let data = try session.data()
        try store(session: data, for: address)
    }
}
