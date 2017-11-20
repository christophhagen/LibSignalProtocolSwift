//
//  SenderMessageKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct SenderMessageKey {

    private static let infoMaterial = [UInt8]("WhisperGroup".utf8)

    private static let ivLength = 16
    private static let cipherKeyLength = 32
    private static let secretLength = ivLength + cipherKeyLength

    var iteration: UInt32

    var iv: [UInt8]

    var cipherKey: [UInt8]

    var seed: [UInt8]

    init(iteration: UInt32, seed: [UInt8]) throws {
        let salt = [UInt8](repeating: 0, count: RatchetChainKey.hashOutputSize)

        let kdf = HKDF(messageVersion: .version3)
        let derivative = try kdf.deriveSecrets(material: seed,
                                               salt: salt,
                                               info: SenderMessageKey.infoMaterial,
                                               outputLength: SenderMessageKey.secretLength)

        self.iteration = iteration
        self.seed = seed
        self.iv = Array(derivative[0..<SenderMessageKey.ivLength])
        self.cipherKey = Array(derivative[SenderMessageKey.ivLength..<derivative.count])
    }
}

extension SenderMessageKey {
    
    init(from object: Textsecure_SenderKeyStateStructure.SenderMessageKey) throws {
        guard object.hasIteration, object.hasSeed else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderMessageKey ProtoBuf object")
        }
        try self.init(iteration: object.iteration, seed: [UInt8](object.seed))
    }
    
    var object: Textsecure_SenderKeyStateStructure.SenderMessageKey {
        return Textsecure_SenderKeyStateStructure.SenderMessageKey.with {
            $0.iteration = self.iteration
            $0.seed = Data(self.seed)
        }
    }
}

extension SenderMessageKey: Equatable {
    static func ==(lhs: SenderMessageKey, rhs: SenderMessageKey) -> Bool {
        return lhs.iteration == rhs.iteration &&
            lhs.iv == rhs.iv &&
            lhs.seed == rhs.seed &&
            lhs.cipherKey == rhs.cipherKey
    }
}
