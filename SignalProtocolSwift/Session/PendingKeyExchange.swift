//
//  PendingKeyExchange.swift
//  libsignal-protocol-swift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct PendingKeyExchange {

    var sequence: UInt32

    var localBaseKey: KeyPair

    var localRatchetKey: KeyPair

    var localIdentityKey: RatchetIdentityKeyPair
}


extension PendingKeyExchange {
    
    init(serializedObject object: Textsecure_SessionStructure.PendingKeyExchange) throws {
        self.sequence = object.sequence
        
        self.localBaseKey = KeyPair(
            publicKey: try PublicKey(from: object.localBaseKey),
            privateKey: try PrivateKey(from: object.localBaseKeyPrivate))
        self.localRatchetKey = KeyPair(
            publicKey: try PublicKey(from: object.localRatchetKey),
            privateKey: try PrivateKey(from: object.localRatchetKeyPrivate))
        self.localIdentityKey = KeyPair(
            publicKey: try PublicKey(from: object.localIdentityKey),
            privateKey: try PrivateKey(from: object.localIdentityKeyPrivate))
    }
    
    init(serializedData data: Data) throws {
        let object = try Textsecure_SessionStructure.PendingKeyExchange(serializedData: data)
        try self.init(serializedObject: object)
    }
    
    func serializedData() throws -> Data {
        return try serializedObject().serializedData()
    }
    
    func serializedObject() throws -> Textsecure_SessionStructure.PendingKeyExchange {
        return Textsecure_SessionStructure.PendingKeyExchange.with {
            $0.sequence = self.sequence
            $0.localBaseKey = self.localBaseKey.publicKey.data
            $0.localBaseKeyPrivate = self.localBaseKey.privateKey.data
            $0.localRatchetKey = self.localRatchetKey.publicKey.data
            $0.localRatchetKeyPrivate = self.localRatchetKey.privateKey.data
            $0.localIdentityKey = self.localIdentityKey.publicKey.data
            $0.localIdentityKeyPrivate = self.localIdentityKey.privateKey.data
        }
    }
}

extension PendingKeyExchange: Equatable {
    static func ==(lhs: PendingKeyExchange, rhs: PendingKeyExchange) -> Bool {
        return lhs.sequence == rhs.sequence &&
            lhs.localBaseKey == rhs.localBaseKey &&
            lhs.localRatchetKey == rhs.localRatchetKey &&
            lhs.localIdentityKey == rhs.localIdentityKey
    }
}
