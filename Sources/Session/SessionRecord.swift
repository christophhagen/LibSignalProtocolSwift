//
//  SessionRecord.swift
//  SignalProtocolSwift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The record of a session (and previous sessions) with another party.
 */
final class SessionRecord: ProtocolBufferEquivalent {

    /// The maximum number of archived states
    private static let archivedStatesMax = 40

    /// The current session
    private(set) var state: SessionState

    /// A list of previous sessions, sorted by most recent
    private(set) var previousStates: [SessionState]

    /// Indicates if the session was just created
    private(set) var isFresh: Bool

    /**
     Create a new session record for a session.
     - note: If the `state` parameter is nil, then a 'fresh' session record is created.
     - parameter state: The session state.
    */
    init(state: SessionState?) {
        if state == nil {
            self.state = SessionState()
            self.isFresh = true
        } else {
            self.state = state!
            self.isFresh = false
        }
        self.previousStates = [SessionState]()
    }

    /**
     Check if the session record contains a specific state.
     - parameter baseKey: The key used for the session.
     - returns: `true`, if a session exists for the given key
     */
    func hasSessionState(baseKey: PublicKey) -> Bool {
        if state.aliceBaseKey == baseKey {
            return true
        }
        return previousStates.contains {
            $0.aliceBaseKey == baseKey
        }
    }

    /**
     Create a new state and archive the old one.
     */
    func archiveCurrentState() {
        let newState = SessionState()
        promoteState(state: newState)
    }

    /**
     Make a state the currently active state.
     - note: Will remove the oldest states if the maximum number of states is reached.
     - parameter state: The new current state.
     */
    func promoteState(state: SessionState) {
        // Remove state if it already exists
        if let baseKey = state.aliceBaseKey {
            removeState(for: baseKey)
        }
        // Move the previously current state to the list of previous states
        previousStates.insert(self.state, at: 0)

        // Make the promoted state the current state
        self.state = state

        // Remove any previous nodes beyond the maximum length
        if previousStates.count > SessionRecord.archivedStatesMax {
            previousStates = Array(previousStates[0..<SessionRecord.archivedStatesMax])
        }
    }

    /**
     Remove a state from the previous states.
     - parameter baseKey: The key used for the session.
     */
    private func removeState(for baseKey: PublicKey) {
        if let i = previousStates.index(where: { $0.aliceBaseKey == baseKey }) {
            previousStates.remove(at: i)
        }
    }

    // MARK: Protocol Buffers

    /// Convert the record to a ProtoBuf object for storage
    var protoObject: Signal_Record {
        return Signal_Record.with {
            $0.currentSession = self.state.protoObject
            $0.previousSessions = self.previousStates.map { $0.protoObject }
        }
    }

    /**
     Create a session record from a ProtoBuf object.
     - parameter protoObject: The ProtoBuf object.
     - throws: `SignalError` error of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from protoObject: Signal_Record) throws {
        self.state = try SessionState(from: protoObject.currentSession)
        self.previousStates = try protoObject.previousSessions.map { try SessionState(from: $0) }
        self.isFresh = false
    }
}

// MARK: Protocol Equatable

extension SessionRecord: Equatable {

    /**
     Compare two session records for equality.
     - parameters lhs: The first record
     - parameters rhs: The second record
     - returns: `true`, if the records match
     */
    static func ==(lhs: SessionRecord, rhs: SessionRecord) -> Bool {
        return lhs.state == rhs.state &&
            lhs.isFresh == rhs.isFresh &&
            lhs.previousStates == rhs.previousStates
    }
}
