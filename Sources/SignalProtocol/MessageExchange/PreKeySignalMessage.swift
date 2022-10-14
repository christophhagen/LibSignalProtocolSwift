//
//  PreKeySignalMessage.swift
//  SignalProtocolSwift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A `PreKeySignalMessage` can be used to establish a new session.
 */
public struct PreKeySignalMessage {

    /// The pre key id of the one time key from the other party
    let preKeyId: UInt32?

    /// The id of the signed pre key used for the message
    let signedPreKeyId: UInt32

    /// The base key used for the message
    let baseKey: PublicKey

    /// The identity key of the sender
    let identityKey: PublicKey

    /// The message included in the pre key message
    let message: SignalMessage

    /**
     Create a new pre key message.
     - parameter preKeyId: The pre key id of the one time key from the other party
     - parameter signedPreKeyId: The id of the signed pre key used for the message
     - parameter baseKey: The base key used for the message
     - parameter identityKey: The identity key of the sender
     - parameter message: The message included in the pre key message
     */
    init(preKeyId: UInt32?,
         signedPreKeyId: UInt32,
         baseKey: PublicKey,
         identityKey: PublicKey,
         message: SignalMessage) {

        self.preKeyId = preKeyId
        self.signedPreKeyId = signedPreKeyId
        self.baseKey = baseKey
        self.identityKey = identityKey
        self.message = message
    }

    /**
     Get the serialized message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`
    */
    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .preKey, data: try self.protoData())
    }
}

// MARK: Protocol buffers

extension PreKeySignalMessage: ProtocolBufferConvertible {

    /**
     Convert the message to a ProtoBuf object for serialization.
     - returns: The object
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    func asProtoObject() throws -> Signal_PreKeySignalMessage {
        return try Signal_PreKeySignalMessage.with {
            if let id = self.preKeyId {
                $0.preKeyID = id
            }
            $0.signedPreKeyID = self.signedPreKeyId
            $0.baseKey = self.baseKey.data
            $0.identityKey = self.identityKey.data
            $0.message = try self.message.baseMessage().data
        }
    }

    /**
     Create a `PreKeySignalMessage` from a ProtoBuf object.
     - note: The following errors can be thrown:
     `invalidProtoBuf`, if the object has missing or corrupt values.
     - parameter object: The serialized data.
     - throws: `SignalError` errors
     */
    init(from object: Signal_PreKeySignalMessage) throws {
        guard object.hasBaseKey, object.hasMessage, object.hasIdentityKey,
            object.hasSignedPreKeyID else {
                throw SignalError(.invalidProtoBuf, "Missing data in PreKeySignalMessage")
        }
        self.baseKey = try PublicKey(from: object.baseKey)
        self.identityKey = try PublicKey(from: object.identityKey)
        self.message = try SignalMessage(from: object.message)
        self.signedPreKeyId = object.signedPreKeyID
        self.preKeyId = object.hasPreKeyID ? object.preKeyID : nil
    }
}
