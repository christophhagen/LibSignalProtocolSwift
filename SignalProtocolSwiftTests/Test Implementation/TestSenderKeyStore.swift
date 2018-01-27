//
//  TestSenderKeyStore.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import SignalProtocolSwift

class TestSenderKeyStore: SenderKeyStoreDelegate {

    typealias Address = SignalSenderKeyName

    private var senderKeys = [SignalSenderKeyName : Data]()

    func senderKey(for address: SignalSenderKeyName) -> Data? {
        return senderKeys[address]
    }

    func store(senderKey: Data, for address: SignalSenderKeyName) throws {
        senderKeys[address] = senderKey
    }
}
