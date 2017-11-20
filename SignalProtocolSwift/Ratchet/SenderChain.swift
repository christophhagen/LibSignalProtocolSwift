//
//  SenderChain.swift
//  libsignal-protocol-swift
//
//  Created by User on 09.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The sender chain of a ratchet
 */
struct SenderChain {
    var ratchetKey: KeyPair
    var chainKey: RatchetChainKey
    var messageKeys: [UInt32 : RatchetMessageKeys]

    init(ratchetKey: KeyPair, chainKey: RatchetChainKey) {
        self.ratchetKey = ratchetKey
        self.chainKey = chainKey
        self.messageKeys = [:]
    }
}

extension SenderChain {
    
    init(from object: Textsecure_SessionStructure.Chain, version: HKDFVersion) throws {
        self.chainKey = RatchetChainKey(from: object.chainKey, version: version)
        self.ratchetKey = KeyPair(
            publicKey:  try PublicKey(from: object.senderRatchetKey),
            privateKey: try PrivateKey(from: object.senderRatchetKeyPrivate))
        self.messageKeys = [:]
        for item in object.messageKeys.map({ RatchetMessageKeys(from: $0) }) {
            self.messageKeys[item.counter] = item
        }
        
    }

    init(from data: Data, version: HKDFVersion) throws {
        let object = try Textsecure_SessionStructure.Chain(serializedData: data)
        try self.init(from: object, version: version)
    }

    func data() throws -> Data {
        return try object.serializedData()
    }

    var object: Textsecure_SessionStructure.Chain {
        return Textsecure_SessionStructure.Chain.with {
            $0.senderRatchetKey = ratchetKey.publicKey.data
            $0.senderRatchetKeyPrivate = ratchetKey.privateKey.data
            $0.chainKey = chainKey.object
            $0.messageKeys = messageKeys.values.map { $0.object }
        }
    }
}

extension SenderChain: Equatable {
    static func ==(lhs: SenderChain, rhs: SenderChain) -> Bool {
        return lhs.ratchetKey == rhs.ratchetKey &&
            lhs.chainKey == rhs.chainKey &&
            lhs.messageKeys == rhs.messageKeys
    }
}
