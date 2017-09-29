//
//  TestPreKeyStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import TestC

class TestPreKeyStore: PreKeyStoreDelegate {

    func setNextPreKeyID(_ id: UInt32) {
        nextPreKeyID = id
    }
    
    var nextPreKeyID: UInt32 = 1

    private var keys = [UInt32 : [UInt8]]()

    func preKey(for id: UInt32) -> [UInt8]? {
        return keys[id]
    }

    func store(preKey: [UInt8], for id: UInt32) -> Bool {
        keys[id] = preKey
        return true
    }

    func containsPreKey(for id: UInt32) -> Bool {
        return keys[id] != nil
    }


    func removePreKey(for id: UInt32) -> Bool {
        if keys[id] == nil {
            return false
        }
        keys[id] = nil
        return true
    }

    func cleanUp() {
        keys.removeAll()
    }


}
