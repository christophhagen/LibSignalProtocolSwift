//
//  RatchetRootKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct RatchetRootKey {
    private static let keyInfo = [UInt8]("WhisperRatchet".utf8)

    static let secretSize = 32
    static let derivedRootSecretsSize = secretSize + RatchetChainKey.secretSize

    let kdf: HKDF

    let key: [UInt8]

    init(kdf: HKDF, key: [UInt8]) {
        self.kdf = kdf
        self.key = key
    }

    func createChain(theirRatchetKey: PublicKey, ourRatchetKey: PrivateKey) throws -> (rootKey: RatchetRootKey, chainKey: RatchetChainKey) {
        let sharedSecret = try theirRatchetKey.calculateAgreement(privateKey: ourRatchetKey)
        let derivedSecret = try kdf.deriveSecrets(
            material: sharedSecret,
            salt: key,
            info: RatchetRootKey.keyInfo,
            outputLength: RatchetRootKey.derivedRootSecretsSize)

        let rootKeySecret = Array(derivedSecret[0..<RatchetRootKey.secretSize])
        let newRootKey = RatchetRootKey(kdf: kdf, key: rootKeySecret)

        let chainKeySecret = Array(derivedSecret[RatchetRootKey.secretSize..<RatchetRootKey.derivedRootSecretsSize])
        let newChainKey = RatchetChainKey(kdf: kdf, key: chainKeySecret, index: 0)

        return (newRootKey, newChainKey)
    }

}

extension RatchetRootKey {
    
    init(from data: Data, version: HKDFVersion) {
        self.key =  [UInt8](data)
        self.kdf = HKDF(messageVersion: version)
    }
    
    var data: Data {
        return Data(key)
    }
}

extension RatchetRootKey: Comparable {
    static func <(lhs: RatchetRootKey, rhs: RatchetRootKey) -> Bool {
        if lhs.kdf != rhs.kdf {
            return lhs.kdf < rhs.kdf
        }
        if lhs.key.count != rhs.key.count {
            return lhs.key.count < rhs.key.count
        }
        for i in 0..<lhs.key.count {
            if lhs.key[i] != rhs.key[i] {
                return lhs.key[i] < rhs.key[i]
            }
        }
        return false
    }

    static func ==(lhs: RatchetRootKey, rhs: RatchetRootKey) -> Bool {
        if lhs.kdf != rhs.kdf {
            return false
        }
        return lhs.key == rhs.key
    }
}
