//
//  SenderChainKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct SenderChainKey {

    private static let messageKeySeed: [UInt8] = [0x01]
    private static let chainKeySeed: [UInt8] = [0x02]

    let iteration: UInt32

    let chainKey: [UInt8]

    init(iteration: UInt32, chainKey: [UInt8]) {
        self.iteration = iteration
        self.chainKey = chainKey
    }

    func messageKey() throws -> SenderMessageKey {
        let derivative = try createDerivative(seed: SenderChainKey.messageKeySeed)
        return try SenderMessageKey(iteration: iteration, seed: derivative)
    }

    func next() throws -> SenderChainKey {
        let derivative = try createDerivative(seed: SenderChainKey.chainKeySeed)
        return SenderChainKey(iteration: iteration + 1, chainKey: derivative)
    }

    private func createDerivative(seed: [UInt8]) throws -> [UInt8] {
        return try SignalCrypto.hmacSHA256(for: seed, with: chainKey)
    }
}

extension SenderChainKey {
    
    init(from object: Textsecure_SenderKeyStateStructure.SenderChainKey) throws {
        guard object.hasSeed, object.hasIteration else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderChainKey Protobuf object")
        }
        self.chainKey = [UInt8](object.seed)
        self.iteration = object.iteration
    }

    var object: Textsecure_SenderKeyStateStructure.SenderChainKey {
        return Textsecure_SenderKeyStateStructure.SenderChainKey.with {
            $0.seed = Data(self.chainKey)
            $0.iteration = self.iteration
        }
    }
}

extension SenderChainKey: Equatable {
    static func ==(lhs: SenderChainKey, rhs: SenderChainKey) -> Bool {
        guard lhs.iteration == rhs.iteration else {
            return false
        }
        return lhs.chainKey == rhs.chainKey
    }
}
