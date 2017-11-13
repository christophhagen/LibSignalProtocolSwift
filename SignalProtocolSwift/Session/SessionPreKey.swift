//
//  SessionPreKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct SessionPreKey {

    static let mediumMaxValue: UInt32 = 0xFFFFFF

    var id: UInt32

    var keyPair: KeyPair

    init(id: UInt32, keyPair: KeyPair) {
        self.id = id
        self.keyPair = keyPair
    }
}

extension SessionPreKey {

    var object: Textsecure_PreKeyRecordStructure {
        return Textsecure_PreKeyRecordStructure.with {
            $0.id = self.id
            $0.publicKey = keyPair.publicKey.data
            $0.privateKey = keyPair.privateKey.data
        }
    }
    
    func data() throws -> Data {
        return try object.serializedData()
    }

    init(from object: Textsecure_PreKeyRecordStructure) throws {
        guard object.hasID, object.hasPublicKey, object.hasPrivateKey else {
            throw SignalError.invalidProtoBuf
        }
        self.id = object.id
        self.keyPair = KeyPair(
            publicKey: try PublicKey(from: object.publicKey),
            privateKey: try PrivateKey(from: object.privateKey))
    }
    
    init(from data: Data) throws {
        let object = try Textsecure_PreKeyRecordStructure(serializedData: data)
        try self.init(from: object)
    }
}
