//
//  RatchetRootKey.swift
//  SignalProtocolSwift
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

    /// The current root key
    let key: Data

    /**
     Create a new root key from the components
     - parameter key: The current root key
    */
    init(key: Data) {
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

        return try HKDF.chainAndRootKey(material: sharedSecret, salt: key, info: RatchetRootKey.keyInfo)
    }
}

// MARK: Protocol Buffers

extension RatchetRootKey: ProtocolBufferSerializable {

    /**
     Return the serialized root key
     - returns: The serialized data
     */
    func protoData() -> Data {
        return key
    }

    /**
     Deserialize a root key.
     - parameter data: The serialized key.
     */
    init(from data: Data) {
        self.key =  data
    }
}

// MARK: Protocol Comparable

extension RatchetRootKey: Comparable {

    /**
     Compare two root keys.
     - parameter lhs: The first key
     - parameter rhs: The second key
     - returns: `True`, if the first key is 'smaller' than the second key
     */
    static func <(lhs: RatchetRootKey, rhs: RatchetRootKey) -> Bool {
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

// MARK: Protocol Equatable

extension RatchetRootKey: Equatable {
    /**
     Compare two root keys for equality.
     - parameter lhs: The first key
     - parameter rhs: The second key
     - returns: `True`, if the keys are equal
     */
    static func ==(lhs: RatchetRootKey, rhs: RatchetRootKey) -> Bool {
        return lhs.key == rhs.key
    }
}
