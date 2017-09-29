//
//  TestSenderKeyStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import TestC

class TestSenderKeyStore: SenderKeyStoreDelegate {

    private var keys = [String : [CHAddress : [UInt8]]]()

    func loadSenderKey(for address: CHAddress, and groupID: String) -> [UInt8]? {
        print(#function)
        guard let dict = keys[groupID] else {
            return nil
        }
        return dict[address]
    }

    func store(senderKey: [UInt8], for address: CHAddress, and groupID: String) -> Bool {
        print(#function)
        if keys[groupID] == nil {
            keys[groupID] = [CHAddress : [UInt8]]()
        }
        keys[groupID]![address] = senderKey
        return true
    }

    func cleanUp() {
        keys.removeAll()
    }


}
