//
//  TestIdentityStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import SignalProtocolSwift


class TestIdentityStore: IdentityKeyStoreDelegate {

    typealias Address = SignalAddress

    private var identityKey: Data!

    private var identities = [SignalAddress : Data]()

    func getIdentityKeyData() throws -> Data {
        if identityKey == nil {
            identityKey = try SignalCrypto.generateIdentityKeyPair()
        }
        return identityKey
    }

    func store(identityKeyData: Data) {
        identityKey = identityKeyData
    }

    func identity(for address: SignalAddress) throws -> Data? {
        return identities[address]
    }


    func store(identity: Data?, for address: SignalAddress) throws {
        identities[address] = identity
    }

    init() {
    }
}
