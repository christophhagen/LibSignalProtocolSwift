//
//  SessionSignedPreKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct SessionSignedPreKey {

    var id: UInt32

    var keyPair: KeyPair

    var timestamp: UInt64

    var signature: Data

    init(id: UInt32, timestamp: UInt64, keyPair: KeyPair, signature: Data) {
        self.id = id
        self.keyPair = keyPair
        self.timestamp = timestamp
        self.signature = signature
    }
}

extension SessionSignedPreKey {

    init(from data: Data) throws {
        let object = try Textsecure_SignedPreKeyRecordStructure(serializedData: data)
        try self.init(from: object)
    }
    
    init(from object: Textsecure_SignedPreKeyRecordStructure) throws {
        guard object.hasID, object.hasPublicKey, object.hasPrivateKey,
            object.hasSignature, object.hasTimestamp else {
                throw SignalError.invalidProtoBuf
        }
        self.id = object.id
        self.keyPair = KeyPair(
            publicKey: try PublicKey(from: object.publicKey),
            privateKey: try PrivateKey(from: object.privateKey))
        self.timestamp = object.timestamp
        self.signature = object.signature
    }
    
    var object: Textsecure_SignedPreKeyRecordStructure {
        return Textsecure_SignedPreKeyRecordStructure.with {
            $0.id = self.id
            $0.publicKey = self.keyPair.publicKey.data
            $0.privateKey = self.keyPair.privateKey.data
            $0.timestamp = self.timestamp
            $0.signature = self.signature
        }
    }

    func data() throws -> Data {
        return try object.serializedData()
    }
}
