//
//  SenderKeyMessage.swift
//  SignalProtocolSwift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
import Curve25519

/**
 A sender key message is used to send an encrypted message in an existing group session.
 */
public struct SenderKeyMessage {

    /// The id of the key that was used
    let keyId: UInt32

    /// The iteration of the chain key
    let iteration: UInt32

    /// The encrypted ciphertext
    let cipherText: Data

    /// The signature of the message
    var signature: Data

    /**
     Return the message serialized 
    */
    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .senderKey, data: try self.protoData())
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
        self.keyId = keyId
        self.iteration = iteration
        self.cipherText = cipherText
        // Empty signature for serialization
        self.signature = Data()
        let data = try self.protoData()
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
        guard signature.count == Curve25519.signatureLength else {
            return false
        }
        let record = try self.protoData()
        let length = record.count - Curve25519.signatureLength
        let message = record[0..<length]
        return signatureKey.verify(signature: signature, for: message)
    }
}


extension SenderKeyMessage: ProtocolBufferEquivalent {

    /// Convert the sender key message to a ProtoBuf object
    var protoObject: Signal_SenderKeyMessage {
        return Signal_SenderKeyMessage.with {
            $0.id = self.keyId
            $0.iteration = self.iteration
            $0.ciphertext = Data(self.cipherText)
        }
    }

    /**
     Create a sender key message from a ProtoBuf object.
     - note: The types of errors thrown are:
     `invalidProtoBuf`, if data is missing or corrupt
     - parameter object: The ProtoBuf object
     - throws: `SignalError` errors
     */
    init(from object: Signal_SenderKeyMessage) throws {
        guard object.hasID, object.hasIteration, object.hasCiphertext else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderKeyMessage object")
        }
        self.keyId = object.id
        self.iteration = object.iteration
        self.cipherText = object.ciphertext
        self.signature = Data()
    }

}

extension SenderKeyMessage: ProtocolBufferSerializable {

    /**
     Serialize the message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public func protoData() throws -> Data {
        do {
            return try protoObject.serializedData() + signature
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SenderKeyMessage: \(error)")
        }
    }

    /**
     Create a sender key message from serialized data.
     - note: The types of errors thrown are:
     `invalidProtoBuf`, if data is missing or corrupt
     `invalidSignature`, if the signature length is incorrect
     - parameter data: The serialized data
     - throws: `SignalError` errors
     */
    public init(from data: Data) throws {
        guard data.count > Curve25519.signatureLength else {
            throw SignalError(.invalidProtoBuf, "Too few bytes in data for SenderKeyMessage")
        }
        let length = data.count - Curve25519.signatureLength
        guard length > 1 else {
            throw SignalError(.invalidProtoBuf, "Too few bytes in data for SenderKeyMessage")
        }
        let content = data[0..<length]
        let signature = data[length...]
        let object: Signal_SenderKeyMessage
        do {
            object = try Signal_SenderKeyMessage(serializedData: content)
        } catch {
           throw SignalError(.invalidProtoBuf, "Could not create sender key message object: \(error)")
        }
        try self.init(from: object)
        self.signature = signature
    }
}
