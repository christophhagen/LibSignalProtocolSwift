//
//  RatchetChainKey.swift
//  SignalProtocolSwift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A chain key for the ratchet.
 */
struct RatchetChainKey {

    /// The seed used as input material for the KDF to derive the message keys
    private static let messageKeySeed = Data([0x01])

    /// The seed used as input material for the KDF to derive the chain keys
    private static let chainKeySeed = Data([0x02])

    /// The seed used as info material for the KDF to derive the message keys
    private static let keyMaterialSeed = "WhisperMessageKeys".data(using: .utf8)!

    /// The size of the chain key
    static let secretSize = 32

    /// The size of the HKDF expand output
    static let hashOutputSize = 32

    /// The current key of the ratchet chain, 32 byte
    var key: Data

    /// The current index of the chain
    var index: UInt32

    /**
     Create a ratchet chain key from the components
     - parameter key: The chain key
     - parameter index: The index in the chain
     */
    init(key: Data, index : UInt32) {
        self.key = key
        self.index = index
    }

    /**
     Get the SHA256 HMAC of the seed.
     - parameter seed: The input for the HMAC
     - returns: The HMAC of the seed with the key as the salt
     - throws: `SignalError.hmacError` if CryptoSwift doesn't work */
    private func getBaseMaterial(seed: Data) throws -> Data {
        return try SignalCrypto.hmacSHA256(for: seed, with: key)
    }

    /**
     Get a set of message keys for the Ratchet
     - returns: A set of Ratchet message keys
     - throws: `SignalError` errors on failure
     */
    func messageKeys() throws -> RatchetMessageKeys {
        let inputKeyMaterial = try getBaseMaterial(seed: RatchetChainKey.messageKeySeed)

        let salt = Data(count: RatchetChainKey.hashOutputSize)
        let keyMaterialData =
            try HKDF.deriveSecrets(
                material: inputKeyMaterial,
                salt: salt,
                info: RatchetChainKey.keyMaterialSeed,
                outputLength: RatchetMessageKeys.derivedMessageSecretsSize)

        var temp = index
        let indexData = withUnsafePointer(to: &temp) { Data(bytes: $0, count: MemoryLayout<UInt32>.size) }
        return try RatchetMessageKeys(material: keyMaterialData + indexData)
    }

    /**
     Return the next chain key
     - returns: The next chain key from the KDF
     - throws: `SignalError.hmacError` if CryptoSwift doesn't work
     */
    func next() throws -> RatchetChainKey {
        let nextKey = try getBaseMaterial(seed: RatchetChainKey.chainKeySeed)
        return RatchetChainKey(key: nextKey, index: index + 1)
    }
}

// MARK: Protocol Buffers

extension RatchetChainKey: ProtocolBufferEquivalent {

    /// The chain key converted to a ProtoBuf object
    var protoObject: Signal_Session.Chain.ChainKey {
        return Signal_Session.Chain.ChainKey.with {
            $0.index = self.index
            $0.key = self.key
        }
    }

    /**
     Create a chain key from a ProtoBuf object.
     - parameter protoObject: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from protoObject: Signal_Session.Chain.ChainKey) throws {
        guard protoObject.hasIndex, protoObject.hasKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in RatchetChainKey protobuf object")
        }
        self.index = protoObject.index
        self.key = protoObject.key
    }
}

// MARK: Protocol Equatable

extension RatchetChainKey: Equatable {
    /**
     Compare two SignalMessages for equality.
     - parameter lhs: The first message
     - parameter rhs: The second message
     - returns: `True`, if the chain keys are equal
     */
    static func ==(lhs: RatchetChainKey, rhs: RatchetChainKey) -> Bool {
        return lhs.key == rhs.key && lhs.index == rhs.index
    }
}
