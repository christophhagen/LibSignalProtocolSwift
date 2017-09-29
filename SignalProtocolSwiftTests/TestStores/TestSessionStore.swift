//
//  TestSessionStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import TestC

class TestSessionStore: SessionStoreDelegate {

    private var keys = [CHAddress : [UInt8]]()

    func loadSession(for address: CHAddress) -> [UInt8]? {
        return keys[address]
    }

    func subDeviceSessions(for recipientID: String) -> [DeviceID] {
        return keys.flatMap { (key, _) -> Int32? in
            if key.recipientID == recipientID {
                return key.deviceID
            }
            return nil
        }
    }

    func store(session: [UInt8], for address: CHAddress) -> Bool {
        keys[address] = session
        return true
    }

    func containsSession(for address: CHAddress) -> Bool {
        return keys[address] != nil
    }

    func deleteSession(for address: CHAddress) -> Bool {
        guard keys[address] != nil else {
            return false
        }
        keys[address] = nil
        return true
    }

    func deleteAllSessions(for recipientID: String) -> Int {
        let list = keys.flatMap { (key, _) -> CHAddress? in
            return key.recipientID == recipientID ? key : nil
        }
        for item in list {
            keys[item] = nil
        }
        return list.count
    }

    func cleanUp() {
        keys.removeAll()
    }


}
