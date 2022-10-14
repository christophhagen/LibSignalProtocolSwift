//
//  SenderMessageKey.swift
//  SignalProtocolSwift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A message key in a chain to encrypt/decrypt messages
 */
struct SenderMessageKey {

    /// The info used when creating the keys from the seed
    private static let infoMaterial = "WhisperGroup".data(using: .utf8)!

    /// The length of the initialization vector
    private static let ivLength = 16

    /// The length of the key
    private static let cipherKeyLength = 32

    /// The combined length of iv and key
    private static let secretLength = ivLength + cipherKeyLength

    /// The iteration of the message key in the chain
    var iteration: UInt32

    /// The initialization vector
    var iv: Data

    /// The encryption/decryption key
    var cipherKey: Data

    /// The seed used to derive the key and iv
    private var seed: Data

    /**
     Create a message key from the components.
     - parameter iteration: The iteration of the message key in the chain
     - parameter seed: The seed used to derive the key and iv
     - throws: `SignalError` of type `hmacError`, if the HMAC authentication fails
    */
    init(iteration: UInt32, seed: Data) throws {
        let salt = Data(count: RatchetChainKey.hashOutputSize)
        let derivative = try HKDF.deriveSecrets(
            material: seed,
            salt: salt,
            info: SenderMessageKey.infoMaterial,
            outputLength: SenderMessageKey.secretLength)

        self.iteration = iteration
        self.seed = seed
        self.iv = derivative[0..<SenderMessageKey.ivLength]
        self.cipherKey = derivative.advanced(by: SenderMessageKey.ivLength)
    }
}

// MARK: Protocol Buffers

extension SenderMessageKey: ProtocolBufferEquivalent {

    /// Convert the sender chain key to a ProtoBuf object
    var protoObject: Signal_SenderKeyState.SenderMessageKey {
        return Signal_SenderKeyState.SenderMessageKey.with {
            $0.iteration = self.iteration
            $0.seed = Data(self.seed)
        }
    }

    /**
     Create a message key from a ProtoBuf object.
     - parameter protoObject: The message key ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from protoObject: Signal_SenderKeyState.SenderMessageKey) throws {
        guard protoObject.hasIteration, protoObject.hasSeed else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderMessageKey ProtoBuf object")
        }
        try self.init(iteration: protoObject.iteration, seed: protoObject.seed)
    }
}

// MARK: Equatable protocol

extension SenderMessageKey: Equatable {

    /**
     Compare two sender message keys for equality.
     - parameter lhs: The first key
     - parameter rhs: The second key
     - returns: `True`, if the keys are equal
     */
    static func ==(lhs: SenderMessageKey, rhs: SenderMessageKey) -> Bool {
        return lhs.iteration == rhs.iteration &&
            lhs.iv == rhs.iv &&
            lhs.seed == rhs.seed &&
            lhs.cipherKey == rhs.cipherKey
    }
}
