//
//  KeyPair.swift
//  libsignal-protocol-swift
//
//  Created by User on 11.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A pair of public and private key for elliptic curve cryptopgraphy
 */
public struct KeyPair {

    /// The length of the private and public key in bytes
    static let keyLength = 32

    /// Type declaration (only needed for compatibility)
    static let DJBType: UInt8 = 0x05

    /// The length of a signature in bytes
    static let signatureLength = 64

    /// The length of a VRF signature in bytes
    static let vrfSignatureLength = 96

    /// The length of the VRF verification output in bytes
    static let vrfVerifyLength = 32

    /// The public part of the key pair
    let publicKey: PublicKey

    /// The private part of the key pair
    let privateKey: PrivateKey

    /**
     Create a key pair from existing public and private keys
     - parameter publicKey: The public part of the key pair
     - parameter privateKey: The private part of the key pair
     */
    public init(publicKey: PublicKey, privateKey: PrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    /**
     Create a new random key pair.
     - returns: A new randomly created key pair
     - throws: `SignalError.noRandomBytes`
     */
    public init() throws {
        let newPrivateKey = try PrivateKey()
        let newPublicKey = try PublicKey(privateKey: newPrivateKey)
        self.privateKey = newPrivateKey
        self.publicKey = newPublicKey
    }
}

/**
 Provide the possibility to convert a `KeyPair` from and to bytes
 */
extension KeyPair {
    
    init(from data: Data) throws {
        let object = try Textsecure_IdentityKeyPairStructure(serializedData: data)
        self.publicKey = try PublicKey(from: object.publicKey)
        self.privateKey = try PrivateKey(from: object.privateKey)
    }
    
    func data() throws -> Data {
        let object = Textsecure_IdentityKeyPairStructure.with {
            $0.publicKey = self.publicKey.data
            $0.privateKey = self.privateKey.data
        }
        return try object.serializedData()
    }
}

extension KeyPair: Equatable {

    public static func ==(lhs: KeyPair, rhs: KeyPair) -> Bool {
        return lhs.privateKey == rhs.privateKey && lhs.publicKey == rhs.publicKey
    }
}


