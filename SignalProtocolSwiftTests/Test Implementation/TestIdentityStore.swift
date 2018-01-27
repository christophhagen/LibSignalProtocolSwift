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

    private var localRegistrationID: UInt32!

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

    func getLocalRegistrationID() throws -> UInt32 {
        if localRegistrationID == nil {
            localRegistrationID = try SignalCrypto.generateRegistrationId(extendedRange: false)
        }
        return localRegistrationID
    }

    func isTrusted(identity: Data, for address: SignalAddress) -> Bool {
        guard let id = identities[address] else {
            // Trust if no identity exists for address
            return true
        }
        return id == identity
    }

    func store(identity: Data?, for address: SignalAddress) throws {
        identities[address] = identity
    }

    init() {
    }
}
