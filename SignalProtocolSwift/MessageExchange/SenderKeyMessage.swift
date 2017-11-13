//
//  SenderKeyMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

public struct SenderKeyMessage {

    var messageVersion: UInt8

    var keyId: UInt32

    var iteration: UInt32

    var cipherText: Data

    var signature: Data

    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .senderKey, data: try self.data())
    }

    init(keyId: UInt32, iteration: UInt32, cipherText: Data, signatureKey: PrivateKey) throws {
        self.messageVersion = CipherTextMessage.currentVersion
        self.keyId = keyId
        self.iteration = iteration
        self.cipherText = cipherText
        self.signature = Data()
        let data = try self.data()
        guard data.count < 256 else {
            throw SignalError.invalidSignature
        }
        self.signature = try signatureKey.sign(message: data)
    }

    func verify(signatureKey: PublicKey) -> Bool {
        guard let record = try? self.data() else {
            return false
        }
        let length = record.count - KeyPair.signatureLength
        let message = record[0..<length]
        return signatureKey.verify(signature: signature, for: message)
    }
}


extension SenderKeyMessage {

    public func data() throws -> Data {
        let version = (self.messageVersion << 4) | CipherTextMessage.currentVersion
        return try [version] + object.serializedData() + signature
    }

    var object: Textsecure_SenderKeyMessage {
        return Textsecure_SenderKeyMessage.with {
            $0.id = self.keyId
            $0.iteration = self.iteration
            $0.ciphertext = Data(self.cipherText)
        }
    }

    public init(from data: Data) throws {
        guard data.count > KeyPair.signatureLength else {
            throw SignalError.invalid
        }
        let version = (data[0] & 0xF0) >> 4
        if version < CipherTextMessage.currentVersion {
            throw SignalError.legacyMessage
        }
        if version > CipherTextMessage.currentVersion {
            throw SignalError.invalidVersion
        }
        let length = data.count - KeyPair.signatureLength
        let content = data[1..<length]
        let signature = data[length..<data.count]
        let object = try Textsecure_SenderKeyMessage(serializedData: content)
        try self.init(from: object, version: version, signature: signature)
    }

    init(from object: Textsecure_SenderKeyMessage, version: UInt8, signature: Data) throws {
        guard object.hasID, object.hasIteration, object.hasCiphertext else {
            throw SignalError.invalidProtoBuf
        }
        self.keyId = object.id
        self.iteration = object.iteration
        self.cipherText = object.ciphertext
        self.messageVersion = version
        self.signature = signature
    }
}
