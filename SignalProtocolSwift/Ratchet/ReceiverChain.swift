//
//  ReceiverChain.swift
//  libsignal-protocol-swift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

final class ReceiverChain {

    var ratchetKey: PublicKey
    var chainKey: RatchetChainKey
    var messageKeys = [RatchetMessageKeys]()

    init(ratchetKey: PublicKey, chainKey: RatchetChainKey) {
        self.ratchetKey = ratchetKey
        self.chainKey = chainKey
    }

    func add(messageKey: RatchetMessageKeys) {
        for index in 0..<messageKeys.count {
            if messageKeys[index].counter == messageKey.counter {
                messageKeys[index] = messageKey
                return
            }
        }
        messageKeys.insert(messageKey, at: 0)
        if messageKeys.count > SenderKeyState.messageKeyMaximum {
            messageKeys.removeLast(messageKeys.count - SenderKeyState.messageKeyMaximum)
        }
    }

    func has(messageKey: RatchetMessageKeys) -> Bool {
        for item in messageKeys {
            if item.counter == messageKey.counter {
                return true
            }
        }
        return false
    }

    func messageKey(for iteration: UInt32) -> RatchetMessageKeys? {
        for item in messageKeys {
            if item.counter == iteration {
                return item
            }
        }
        return nil
    }

    func removeMessageKey(for iteration: UInt32) -> RatchetMessageKeys? {
        for index in 0..<messageKeys.count {
            if messageKeys[index].counter == iteration {
                return messageKeys.remove(at: index)
            }
        }
        return nil
    }
    
    // MARK: ProtocolBuffer
    
    init(from object: Textsecure_SessionStructure.Chain, version: HKDFVersion) throws {
        self.ratchetKey = try PublicKey(from: object.senderRatchetKey)
        self.chainKey = RatchetChainKey(from: object.chainKey, version: version)
        self.messageKeys = object.messageKeys.map { RatchetMessageKeys(from: $0) }
    }

    // TODO: Remove?
//    convenience init(from data: Data, version: HKDFVersion) throws {
//        let object = try Textsecure_SessionStructure.Chain(serializedData: data)
//        try self.init(from: object, version: version)
//    }
//
//    func data() throws -> Data {
//        return try object.serializedData()
//    }
    
    var object: Textsecure_SessionStructure.Chain {
        return Textsecure_SessionStructure.Chain.with {
            $0.senderRatchetKey = ratchetKey.data
            $0.chainKey = chainKey.object
            $0.messageKeys = messageKeys.map { $0.object }
        }
    }
}

extension ReceiverChain: Equatable {
    static func ==(lhs: ReceiverChain, rhs: ReceiverChain) -> Bool {
        return lhs.ratchetKey == rhs.ratchetKey &&
            lhs.chainKey == rhs.chainKey &&
            lhs.messageKeys == rhs.messageKeys
    }
}
