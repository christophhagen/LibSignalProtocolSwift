//
//  PreKeySignalMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

public struct PreKeySignalMessage {

    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .preKey, data: try self.data())
    }

    var version: UInt8

    var registrationId: UInt32

    var preKeyId: UInt32?

    var signedPreKeyId: UInt32

    var baseKey: PublicKey

    var identityKey: PublicKey

    var message: SignalMessage

    init(messageVersion: UInt8,
         registrationId: UInt32,
         preKeyId: UInt32?,
         signedPreKeyId: UInt32,
         baseKey: PublicKey,
         identityKey: PublicKey,
         message: SignalMessage) {

        self.version = messageVersion
        self.registrationId = registrationId
        self.preKeyId = preKeyId
        self.signedPreKeyId = signedPreKeyId
        self.baseKey = baseKey
        self.identityKey = identityKey
        self.message = message
    }
}

extension PreKeySignalMessage {
    
    public func data() throws -> Data {
        let ver = (version << 4) | CipherTextMessage.currentVersion
        return try Data([ver]) + object().serializedData()
    }
    
    func object() throws -> Textsecure_PreKeySignalMessage {
        return try Textsecure_PreKeySignalMessage.with {
            if let id = self.preKeyId {
                $0.preKeyID = id
            }
            $0.signedPreKeyID = self.signedPreKeyId
            $0.baseKey = self.baseKey.data
            $0.identityKey = self.identityKey.data
            $0.message = try self.message.baseMessage().data
            $0.registrationID = self.registrationId
        }
    }
    
    public init(from data: Data) throws {
        guard data.count > 1 else {
            throw SignalError.invalidProtoBuf
        }
        let ver = (data[0] & 0xF0) >> 4
        guard ver > CipherTextMessage.unsupportedVersion,
            ver <= CipherTextMessage.currentVersion else {
                signalLog(level: .warning, "Invalid version of PreKeySignalMessage: \(ver)")
                throw SignalError.invalidVersion
        }
        let object = try Textsecure_PreKeySignalMessage(serializedData: data.advanced(by: 1))
        try self.init(from: object, version: ver)
    }

    init(from object: Textsecure_PreKeySignalMessage, version: UInt8) throws {
        guard object.hasBaseKey, object.hasMessage, object.hasIdentityKey,
            object.hasSignedPreKeyID, object.hasRegistrationID else {
                throw SignalError.invalidProtoBuf
        }
        self.baseKey = try PublicKey(from: object.baseKey)
        self.identityKey = try PublicKey(from: object.identityKey)
        self.registrationId = object.registrationID
        self.message = try SignalMessage(from: object.message)
        self.signedPreKeyId = object.signedPreKeyID
        if object.hasPreKeyID {
            self.preKeyId = object.preKeyID
        }
        self.version = version
    }
}
