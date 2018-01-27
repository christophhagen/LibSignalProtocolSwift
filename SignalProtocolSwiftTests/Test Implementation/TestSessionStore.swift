//
//  TestSessionStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import SignalProtocolSwift

class TestSessionStore: SessionStoreDelegate {

    typealias Address = SignalAddress

    private var sessions = [Address : Data]()

    func loadSession(for address: Address) -> Data? {
        return sessions[address]
    }

    func subDeviceSessions(for recipientID: String) -> [UInt32] {
        return sessions.keys.filter { $0.identifier == recipientID }.map { $0.deviceId }
    }

    func store(session: Data, for address: Address) throws {
        sessions[address] = session
    }

    func containsSession(for address: Address) -> Bool {
        return sessions[address] != nil
    }

    func deleteSession(for address: Address) throws {
        sessions[address] = nil
    }

    func deleteAllSessions(for recipientID: String) -> Int {
        var count = 0
        for key in sessions.keys.filter({ $0.identifier == recipientID }) {
            sessions[key] = nil
            count += 1
        }
        return count
    }
}
