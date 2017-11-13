//
//  SessionRecord.swift
//  libsignal-protocol-swift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


final class SessionRecord {

    static let archivedStatesMax = 40

    var state: SessionState

    var previousStates: [SessionState]

    var isFresh: Bool

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

    func hasSessionState(version: UInt8, baseKey: PublicKey) -> Bool {
        if state.version == version && state.aliceBaseKey == baseKey {
            return true
        }
        for item in previousStates {
            if item.version == version && item.aliceBaseKey == baseKey {
                return true
            }
        }
        return false
    }

    func archiveCurrentState() {
        let newState = SessionState()
        promoteState(state: newState)
    }

    func promoteState(state: SessionState) {
        // Move the previously current state to the list of previous states
        previousStates.insert(self.state, at: 0)

        // Make the promoted state the current state
        self.state = state

        // Remove any previous nodes beyond the maximum length
        if previousStates.count > SessionRecord.archivedStatesMax {
            previousStates = Array(previousStates[0..<SessionRecord.archivedStatesMax])
        }
    }

    func data() throws -> Data {
        return try object().serializedData()
    }

    func object() throws -> Textsecure_RecordStructure {
        return try Textsecure_RecordStructure.with {
            $0.currentSession = try self.state.object()
            $0.previousSessions = try self.previousStates.map { try $0.object() }
        }
    }

    convenience init(from data: Data) throws {
        let object = try Textsecure_RecordStructure(serializedData: data)
        try self.init(from: object)

    }

    init(from object: Textsecure_RecordStructure) throws {
        self.state = try SessionState(from: object.currentSession)
        self.previousStates = try object.previousSessions.map { try SessionState(from: $0) }
        self.isFresh = false
    }
}

extension SessionRecord: Equatable {
    static func ==(lhs: SessionRecord, rhs: SessionRecord) -> Bool {
        return lhs.state == rhs.state &&
            lhs.isFresh == rhs.isFresh &&
            lhs.previousStates == rhs.previousStates
    }
}
