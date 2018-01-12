//
//  SenderKeyMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A sender key message is used to send an encrypted message in an existing group session.
 */
public struct SenderKeyMessage {

    /// The version of the message
    var messageVersion: UInt8

    /// The id of the key that was used
    var keyId: UInt32

    /// The iteration of the chain key
    var iteration: UInt32

    /// The encrypted ciphertext
    var cipherText: Data

    /// The signature of the message
    var signature: Data

    /**
     Return the message serialized 
    */
    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .senderKey, data: try self.data())
    }

    /**
     Create a `SenderKeyMessage` from the components.
     - note: The possible error types are:
     `invalidProtoBuf`, if the ProtoBuf object can't be serialized for the signature.
     `invalidLength`, if the message is more than 256 or 0 byte.
     `invalidSignature`, if the message could not be signed.
     `noRandomBytes`, if the crypto provider could not provide random bytes for the signature.
     - parameter keyId: The id of the key that was used
     - parameter iteration: The iteration of the chain key
     - parameter cipherText: The encrypted ciphertext
     - parameter signatureKey: The key used for the message signature
     - throws: `SignalError` errors
    */
    init(keyId: UInt32, iteration: UInt32, cipherText: Data, signatureKey: PrivateKey) throws {
        self.messageVersion = CipherTextMessage.currentVersion
        self.keyId = keyId
        self.iteration = iteration
        self.cipherText = cipherText
        // Empty signature for serialization
        self.signature = Data()
        let data = try self.data()
        self.signature = try signatureKey.sign(message: data)
    }

    /**
     Verify that the signature matches the message.
     - note: The possible error types are:

     - parameter signatureKey: The key used to verify the message
     - returns: `True`, if the signature matches
     - throws: `SignalError` of type `invalidProtoBuf`, if the ProtoBuf object can't be serialized for the signature.
    */
    func verify(signatureKey: PublicKey) throws -> Bool {
        guard signature.count == KeyPair.signatureLength else {
            return false
        }
        let record = try self.data()
        let length = record.count - KeyPair.signatureLength
        let message = record[0..<length]
        return signatureKey.verify(signature: signature, for: message)
    }
}


extension SenderKeyMessage {

    /**
     Serialize the message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public func data() throws -> Data {
        let version = (self.messageVersion << 4) | CipherTextMessage.currentVersion
        do {
            return try [version] + object.serializedData() + signature
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SenderKeyMessage: \(error)")
        }
    }

    /// Convert the sender key message to a ProtoBuf object
    var object: Textsecure_SenderKeyMessage {
        return Textsecure_SenderKeyMessage.with {
            $0.id = self.keyId
            $0.iteration = self.iteration
            $0.ciphertext = Data(self.cipherText)
        }
    }

    /**
     Create a sender key message from serialized data.
     - note: The types of errors thrown are:
     `invalidProtoBuf`, if data is missing or corrupt
     `invalidSignature`, if the signature length is incorrect
     `legacyMessage`, if the message version is older than the current version
     `invalidVersion`, if the message version is newer than the current version
     - parameter data: The serialized data
     - throws: `SignalError` errors
     */
    public init(from data: Data) throws {
        guard data.count > KeyPair.signatureLength else {
            throw SignalError(.invalidProtoBuf, "Too few bytes in data for SenderKeyMessage")
        }
        let version = (data[0] & 0xF0) >> 4
        let length = data.count - KeyPair.signatureLength
        guard length > 1 else {
            throw SignalError(.invalidProtoBuf, "Too few bytes in data for SenderKeyMessage")
        }
        let content = data[1..<length]
        let signature = data[length..<data.count]
        let object: Textsecure_SenderKeyMessage
        do {
            object = try Textsecure_SenderKeyMessage(serializedData: content)
        } catch {
           throw SignalError(.invalidProtoBuf, "Could not create sender key message object: \(error)")
        }
        try self.init(from: object, version: version, signature: signature)
    }

    /**
     Create a sender key message from a ProtoBuf object.
     - note: The types of errors thrown are:
     `invalidProtoBuf`, if data is missing or corrupt
     `invalidSignature`, if the signature length is incorrect
     `legacyMessage`, if the message version is older than the current version
     `invalidVersion`, if the message version is newer than the current version
     - parameter object: The ProtoBuf object
     - throws: `SignalError` errors
     */
    init(from object: Textsecure_SenderKeyMessage, version: UInt8, signature: Data) throws {
        if version < CipherTextMessage.currentVersion {
            throw SignalError(.legacyMessage, "Old SenderKeyMessage version \(version)")
        }
        if version > CipherTextMessage.currentVersion {
            throw SignalError(.invalidVersion, "Unknown SenderKeyMessage version \(version)")
        }
        guard object.hasID, object.hasIteration, object.hasCiphertext else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderKeyMessage object")
        }
        guard signature.count == KeyPair.signatureLength else {
            throw SignalError(.invalidSignature, "Invalid signature length \(signature.count)")
        }
        self.keyId = object.id
        self.iteration = object.iteration
        self.cipherText = object.ciphertext
        self.messageVersion = version
        self.signature = signature
    }
}
