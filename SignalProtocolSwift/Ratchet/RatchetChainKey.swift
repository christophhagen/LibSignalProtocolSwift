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
    private static let messageKeySeed: [UInt8] = [0x01]

    /// The seed used as input material for the KDF to derive the chain keys
    private static let chainKeySeed: [UInt8] = [0x02]

    /// The seed used as info material for the KDF to derive the message keys
    private static let keyMaterialSeed = [UInt8]("WhisperMessageKeys".utf8)

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
    var key: [UInt8]

    /// The current index of the chain
    var index: UInt32

    init(kdf: HKDF, key: [UInt8], index : UInt32) {
        self.kdf = kdf
        self.key = key
        self.index = index
    }

    /**
     Get the SHA256 HMAC of the seed.
     - parameter seed: The input for the HMAC
     - returns: The HMAC of the seed with the key as the salt
     - throws: `SignalError.hmacError` if CryptoSwift doesn't work */
    private func getBaseMaterial(seed: [UInt8]) throws -> [UInt8] {
        return try SignalCrypto.hmacSHA256(for: seed, with: key)
    }

    /**
     Get a set of message keys for the Ratchet
     - returns: A set of Ratchet message keys
     - throws: `SignalError` errors on failure
     */
    func messageKeys() throws -> RatchetMessageKeys {
        let inputKeyMaterial = try getBaseMaterial(seed: RatchetChainKey.messageKeySeed)

        let salt = [UInt8](repeating: 0, count: RatchetChainKey.hashOutputSize)
        let keyMaterialData =
            try kdf.deriveSecrets(
                material: inputKeyMaterial,
                salt: salt,
                info: RatchetChainKey.keyMaterialSeed,
                outputLength: RatchetMessageKeys.derivedMessageSecretsSize)

        return try RatchetMessageKeys(from: keyMaterialData + index.asByteArray)
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
    
    init(from object: Textsecure_SessionStructure.Chain.ChainKey, version: HKDFVersion) {
        self.index = object.index
        self.key = [UInt8](object.key)
        self.kdf = HKDF(messageVersion: version)
    }
    
    init(from data: Data, version: HKDFVersion) throws {
        let object = try Textsecure_SessionStructure.Chain.ChainKey(serializedData: data)
        self.init(from: object, version: version)
    }

    func data() throws -> Data {
        return try object.serializedData()
    }

    var object: Textsecure_SessionStructure.Chain.ChainKey {
        return Textsecure_SessionStructure.Chain.ChainKey.with {
            $0.index = self.index
            $0.key = Data(self.key)
        }
    }
}

extension RatchetChainKey: Equatable {
    static func ==(lhs: RatchetChainKey, rhs: RatchetChainKey) -> Bool {
        return lhs.kdf == rhs.kdf &&
        lhs.key == rhs.key &&
        lhs.index == rhs.index
    }
}
