//
//  SenderChainKey.swift
//  SignalProtocolSwift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A key in the sender chain.
 */
struct SenderChainKey {

    /// The seed value for the message key when deriving the next key
    private static let messageKeySeed = Data([0x01])

    /// The seed value for the chain key when deriving the next key
    private static let chainKeySeed = Data([0x02])

    /// The current iteration of the chain
    var iteration: UInt32

    /// The current chain key
    var chainKey: Data

    /**
     Create a new chain key from the components.
     - parameter iteration: The current iteration of the chain
     - parameter chainKey: The data of the current chain key
    */
    init(iteration: UInt32, chainKey: Data) {
        self.iteration = iteration
        self.chainKey = chainKey
    }

    /**
     Advance the chain and return the generated message key.
     - returns: The message key
     - throws: `SignalError` of type `hmacError`, if the HMAC could not be calculated for the chain key, or the authentication fails
    */
    mutating func messageKey() throws -> SenderMessageKey {
        let derivative = try SignalCrypto.hmacSHA256(for: SenderChainKey.messageKeySeed, with: chainKey)
        let messageKey = try SenderMessageKey(iteration: iteration, seed: derivative)
        chainKey = Data(derivative)
        iteration += 1
        return messageKey
    }
}

// MARK: Protocol Buffers

extension SenderChainKey: ProtocolBufferEquivalent {

    /// Convert the sender chain key to a ProtoBuf object
    var protoObject: Signal_SenderKeyState.SenderChainKey {
        return Signal_SenderKeyState.SenderChainKey.with {
            $0.seed = self.chainKey
            $0.iteration = self.iteration
        }
    }

    /**
     Create a chain key from a ProtoBuf object.
     - parameter protoObject: The chain key ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from protoObject: Signal_SenderKeyState.SenderChainKey) throws {
        guard protoObject.hasSeed, protoObject.hasIteration else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderChainKey Protobuf object")
        }
        self.chainKey = protoObject.seed
        self.iteration = protoObject.iteration
    }
}

// MARK: Protocol Equatable

extension SenderChainKey: Equatable {
    /**
     Compare two sender chain keys for equality.
     - parameter lhs: The first key
     - parameter rhs: The second key
     - returns: `True`, if the keys are equal
     */
    static func ==(lhs: SenderChainKey, rhs: SenderChainKey) -> Bool {
        guard lhs.iteration == rhs.iteration else {
            return false
        }
        return lhs.chainKey == rhs.chainKey
    }
}
