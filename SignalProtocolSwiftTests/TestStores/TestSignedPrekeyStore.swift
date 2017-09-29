//
//  TestSignedPrekeyStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import TestC

class TestSignedPreKeyStore: SignedPreKeyStoreDelegate {

    private var keys = [UInt32 : [UInt8]]()

    func signedPreKey(for id: UInt32) -> [UInt8]? {
        return keys[id]
    }

    func store(signedPreKey: [UInt8], for id: UInt32) -> Bool {
        keys[id] = signedPreKey
        return true
    }

    func containsSignedPreKey(for id: UInt32) -> Bool {
        return keys[id] != nil
    }

    func removeSignedPreKey(for id: UInt32) -> Bool {
        guard keys[id] != nil else {
            return false
        }
        keys[id] = nil
        return true
    }

    func cleanUp() {
        keys.removeAll()
    }
}
