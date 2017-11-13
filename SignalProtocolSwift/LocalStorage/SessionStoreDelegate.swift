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
 unspecified data blobs. Register your implementation with an instance of `KeyStore` to
 receive events.
 */
public protocol SessionStoreDelegate {

    /**
     Load a session for a given address.

     - parameter address: The address of the remote client
     - returns: The session record, or nil if no record exists
     */
    func loadSession(for address: SignalAddress) -> Data?

    /**
     Retreive the recipient IDs of all active sessions for a remote client.

     - parameter recipientID: The name of the remote client.
     - returns: An array of recipient IDs
     */
    func subDeviceSessions(for recipientID: String) -> [Int32]

    /**
     Store a session record for a remote client.

     - parameter session: The session record to store
     - parameter address: The address of the remote client
     - returns: `true` on success, `false` on error
     */
    func store(session: Data, for address: SignalAddress) -> Bool

    /**
     Indicate if a record exists for the client address

     - parameter address: The address of the remote client
     - returns: `true` if a record exists
     */
    func containsSession(for address: SignalAddress) -> Bool

    /**
     Delete a session for a remote client.

     - parameter address: The address of the remote client
     - returns: `true` if the session was deleted
     */
    func deleteSession(for address: SignalAddress) -> Bool

    /**
     Delete all session records for a given client.

     - parameter recipientID: The name of the remote client
     - returns: The number of deleted records
     */
    func deleteAllSessions(for recipientID: String) -> Int

}
