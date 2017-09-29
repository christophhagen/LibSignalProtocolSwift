//
//  TestIdentityKeyStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import TestC

class TestIdentityKeyStore: IdentityKeyStoreDelegate {

    var identityKey: [UInt8]?

    var localRegistrationID: Int

    private var keys = [CHAddress : [UInt8]]()

    init(identity: [UInt8], registrationID: Int) {
        self.identityKey = identity
        self.localRegistrationID = registrationID
    }

    func isTrustedIdentity(for address: CHAddress, and record: [UInt8]?) -> Bool {
        guard let entry = keys[address], let data = record else {
            return true
        }
        return entry == data
    }

    func saveIdentity(for address: CHAddress, and record: [UInt8]?) -> Bool {
        keys[address] = record
        return true
    }

    func cleanup() {
        keys.removeAll()
    }

}
