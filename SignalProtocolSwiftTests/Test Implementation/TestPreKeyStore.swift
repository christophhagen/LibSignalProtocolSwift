//
//  TestPreKeyStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import SignalProtocolSwift

class TestPreKeyStore: PreKeyStoreDelegate {

    typealias Address = SignalAddress

    var lastId: UInt32 = 0

    private var preKeys = [UInt32 : Data]()

    func preKey(for id: UInt32) throws -> Data {
        guard let key = preKeys[id] else {
            throw SignalError(.storageError, "No pre key for id \(id)")
        }
        return key
    }

    func store(preKey: Data, for id: UInt32) throws {
        preKeys[id] = preKey
        lastId = id
    }

    func containsPreKey(for id: UInt32) -> Bool {
        return preKeys[id] != nil
    }

    func removePreKey(for id: UInt32) throws {
        preKeys[id] = nil
    }

}
