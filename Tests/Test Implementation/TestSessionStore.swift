//
//  TestSessionStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import Foundation
import SignalProtocol

/**
 Implement the `SessionStore` protocol to handle the session records of the Signal Protocol.
 */
class TestSessionStore: SessionStore {

    /// The type that distinguishes different devices/users
    typealias Address = SignalAddress

    /// Dictionary of the sessions
    private var sessions = [Address : Data]()

    /**
     Load a session for a given address.
     - parameter address: The address of the remote client
     - returns: The session record, or nil if no record exists
     */
    func loadSession(for address: Address) -> Data? {
        return sessions[address]
    }

    /**
     Store a session record for a remote client.
     - parameter session: The session record to store
     - parameter address: The address of the remote client
     - returns: `true` on success, `false` on error
     */
    func store(session: Data, for address: Address) throws {
        sessions[address] = session
    }

    /**
     Indicate if a record exists for the client address
     - parameter address: The address of the remote client
     - returns: `true` if a record exists
     */
    func containsSession(for address: Address) -> Bool {
        return sessions[address] != nil
    }

    /**
     Delete a session for a remote client.
     - parameter address: The address of the remote client
     - returns: `true` if the session was deleted
     */
    func deleteSession(for address: Address) throws {
        sessions[address] = nil
    }
}
