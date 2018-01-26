//
//  RatchetRootKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A root key is within a ratchet to derive new sender and receiver chain keys.
 */
struct RatchetRootKey {

    /// Bytes used as input for the KDF
    private static let keyInfo = "WhisperRatchet".data(using: .utf8)!

    /// The number of bytes for the root key
    static let secretSize = 32

    /// The key derivation function for the root key
    private let kdf: HKDF

    /// The current root key
    let key: Data

    /**
     Create a new root key from the components
     - parameter kdf: The key derivation function
     - parameter key: The current root key
    */
    init(kdf: HKDF, key: Data) {
        self.kdf = kdf
        self.key = key
    }

    /**
     Create a new root key and chain key.
     - parameter theirRatchetKey: The ratchet key from the other party.
     - parameter ourRatchetKey: The local ratchet key
     - throws: `SignalError.hmacError`, if the HMAC authentication fails
     - returns: A tuple of the root key and chain key
    */
    func createChain(theirRatchetKey: PublicKey, ourRatchetKey: PrivateKey) throws -> (rootKey: RatchetRootKey, chainKey: RatchetChainKey) {
        let sharedSecret = try theirRatchetKey.calculateAgreement(privateKey: ourRatchetKey)

        return try kdf.chainAndRootKey(material: sharedSecret, salt: key, info: RatchetRootKey.keyInfo)
    }
}

// MARK: Protocol Buffers

extension RatchetRootKey {

    /**
     Deserialize a root key.
     - parameter data: The serialized key.
     - parameter version: The KDF version
    */
    init(from data: Data, version: HKDFVersion) {
        self.key =  data
        self.kdf = HKDF(messageVersion: version)
    }

    /// The serialized root key
    var data: Data {
        return key
    }
}

extension RatchetRootKey: Comparable {

    /**
     Compare two root keys.
     - parameter lhs: The first key
     - parameter rhs: The second key
     - returns: `True`, if the first key is 'smaller' than the second key
     */
    static func <(lhs: RatchetRootKey, rhs: RatchetRootKey) -> Bool {
        guard lhs.kdf == rhs.kdf else {
            return lhs.kdf < rhs.kdf
        }
        guard lhs.key.count == rhs.key.count else {
            return lhs.key.count < rhs.key.count
        }
        for i in 0..<lhs.key.count {
            if lhs.key[i] != rhs.key[i] {
                return lhs.key[i] < rhs.key[i]
            }
        }
        return false
    }
}

extension RatchetRootKey: Equatable {
    /**
     Compare two root keys for equality.
     - parameter lhs: The first key
     - parameter rhs: The second key
     - returns: `True`, if the keys are equal
     */
    static func ==(lhs: RatchetRootKey, rhs: RatchetRootKey) -> Bool {
        return lhs.kdf == rhs.kdf && lhs.key == rhs.key
    }
}