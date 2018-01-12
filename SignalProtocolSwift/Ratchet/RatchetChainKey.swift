//
//  RatchetChainKey.swift
//  libsignal-protocol-swift
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

    /**
     The object for the key derivation function
     */
    private let kdf: HKDF

    /**
     The current key of the ratchet chain, 32 byte
     */
    var key: Data

    /// The current index of the chain
    var index: UInt32

    init(kdf: HKDF, key: Data, index : UInt32) {
        self.kdf = kdf
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
            try kdf.deriveSecrets(
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
        return RatchetChainKey(kdf: kdf, key: nextKey, index: index + 1)
    }
}

extension RatchetChainKey {

    /**
     Create a chain key from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from object: Textsecure_SessionStructure.Chain.ChainKey, version: HKDFVersion) throws {
        guard object.hasIndex, object.hasKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in RatchetChainKey protobuf object")
        }
        self.index = object.index
        self.key = object.key
        self.kdf = HKDF(messageVersion: version)
    }

    /**
     Create a ratchet chain key from serialized data.
     - note: The types of errors thrown are:
     `invalidProtoBuf`, if data is missing or corrupt
     - parameter data: The serialized data
     - throws: `SignalError` errors
     */
    init(from data: Data, version: HKDFVersion) throws {
        let object: Textsecure_SessionStructure.Chain.ChainKey
        do {
            object = try Textsecure_SessionStructure.Chain.ChainKey(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create RatchetChainKey object: \(error)")
        }
        try self.init(from: object, version: version)
    }

    /**
     Serialize the key.
     - returns: The serialized keys
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    func data() throws -> Data {
        return try object.serializedData()
    }

    /// The chain key converted to a ProtoBuf object
    var object: Textsecure_SessionStructure.Chain.ChainKey {
        return Textsecure_SessionStructure.Chain.ChainKey.with {
            $0.index = self.index
            $0.key = self.key
        }
    }
}

extension RatchetChainKey: Equatable {
    /**
     Compare two SignalMessages for equality.
     - parameter lhs: The first message
     - parameter rhs: The second message
     - returns: `True`, if the keys are equal
     */
    static func ==(lhs: RatchetChainKey, rhs: RatchetChainKey) -> Bool {
        return lhs.kdf == rhs.kdf && lhs.key == rhs.key && lhs.index == rhs.index
    }
}
