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
final class SessionRecord {

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
     - parameter version: The session version of the searched state.
     - parameter baseKey: The key used for the session.
     - returns: `true`, if a session exists for the given version and key
     */
    func hasSessionState(version: UInt8, baseKey: PublicKey) -> Bool {
        if state.version == version && state.aliceBaseKey == baseKey {
            return true
        }
        return previousStates.contains {
            $0.version == version && $0.aliceBaseKey == baseKey
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
            removeState(for: state.version, and: baseKey)
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
     - parameter version: The session version of the searched state.
     - parameter baseKey: The key used for the session.
     */
    private func removeState(for version: UInt8, and baseKey: PublicKey) {
        if let i = previousStates.index(where: { $0.version == version && $0.aliceBaseKey == baseKey }) {
            previousStates.remove(at: i)
        }
    }

    // MARK: Protocol Buffers

    /**
     Serialize the record for storage.
     - throws: `SignalError` error of type `invalidProtoBuf`, if the ProtoBuf object could not be serialized.
     */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SessionRecord ProtoBuf object: \(error)")
        }
    }

    /// Convert the record to a ProtoBuf object for storage
    var object: Textsecure_RecordStructure {
        return Textsecure_RecordStructure.with {
            $0.currentSession = self.state.object
            $0.previousSessions = self.previousStates.map { $0.object }
        }
    }

    /**
     Create a record from serialized data.
     - parameter data: The serialized record.
     - throws: `SignalError` error of type `invalidProtoBuf`, if data is missing or corrupt
     */
    convenience init(from data: Data) throws {
        let object: Textsecure_RecordStructure
        do {
            object = try Textsecure_RecordStructure(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not deserialize SessionRecord ProtoBuf object: \(error)")
        }
        try self.init(from: object)

    }

    /**
     Create a session record from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` error of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from object: Textsecure_RecordStructure) throws {
        self.state = try SessionState(from: object.currentSession)
        self.previousStates = try object.previousSessions.map { try SessionState(from: $0) }
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
