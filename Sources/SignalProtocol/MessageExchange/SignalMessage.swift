//
//  SignalMessage.swift
//  SignalProtocolSwift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A `SignalMessage` is used to send an encrypted message in an established session.
 */
public struct SignalMessage {

    /// The length of the MAC for a message in bytes
    static let macLength = 8

    /// The public key of the sending ratchet
    let senderRatchetKey: PublicKey

    /// The current counter of the ratchet
    let counter: UInt32

    /// The counter of the previous ratchet
    let previousCounter: UInt32

    /// The encrypted text
    let cipherText: Data

    /// The mac of the message
    var mac: Data

    /**
     Create a SignalMessage from its components.
     - parameter macKey: The key used to calculate the message authentication
     - parameter senderRatchetKey: The public key of the sending ratchet
     - parameter counter: The current counter of the ratchet
     - parameter previousCounter: The counter of the previous ratchet
     - parameter cipherText: The encrypted text
     - parameter senderIdentityKey: The identity of the sender used for the message MAC
     - parameter receiverIdentityKey: The identity of the receiver used for the message MAC
     - throws: `SignalError` of type `invalidProtoBuf`, if the serialization fails.
     `hmacError`, if the message HMAC could not be calculated
    */
    init(macKey: Data,
         senderRatchetKey: PublicKey,
         counter: UInt32,
         previousCounter: UInt32,
         cipherText: Data,
         senderIdentityKey: PublicKey,
         receiverIdentityKey: PublicKey) throws {

        self.senderRatchetKey = senderRatchetKey
        self.counter = counter
        self.previousCounter = previousCounter
        self.cipherText = cipherText
        self.mac = Data()
        self.mac = try getMac(senderIdentityKey: senderIdentityKey,
                              receiverIdentityKey: receiverIdentityKey,
                              macKey: macKey,
                              message: try self.protoData())
    }

    /**
     Calculate the MAC of the message. The length of the MAC is specified by `SignalMessage.macLength`
     - parameter senderIdentityKey: The identity of the sender used for the message MAC
     - parameter receiverIdentityKey: The identity of the receiver used for the message MAC
     - parameter macKey: The key used to calculate the message authentication
     - parameter message: The serialized message to calculate the MAC for
     - throws: `SignalError` of type `hmacError`, if the message HMAC could not be calculated
     - returns: The message authentication data
     */
    private func getMac(senderIdentityKey: PublicKey,
                        receiverIdentityKey: PublicKey,
                        macKey: Data,
                        message: Data) throws -> Data {

        let bytes = senderIdentityKey.data + receiverIdentityKey.data
        let longMac = try SignalCrypto.hmacSHA256(for: bytes +  message, with: macKey)

        guard longMac.count >= SignalMessage.macLength else {
            throw SignalError(.hmacError, "MAC length invalid: Is \(SignalMessage.macLength), Maximum \(longMac.count)")
        }

        return longMac[0..<SignalMessage.macLength]
    }

    /**
     Verify the MAC of the message.
     - parameter senderIdentityKey: The identity of the sender used for the message MAC
     - parameter receiverIdentityKey: The identity of the receiver used for the message MAC
     - parameter macKey: The key used to calculate the message authentication
     - throws: `SignalError` of type `invalidProtoBuf`, if the serialization fails.
     `hmacError`, if the message HMAC could not be calculated
     - returns: `True`, if the message is authentic
     */
    func verifyMac(senderIdentityKey: PublicKey,
                   receiverIdentityKey: PublicKey,
                   macKey: Data) throws -> Bool {

        let data = try self.protoData()
        let length = data.count - SignalMessage.macLength
        let content = data[0..<length]

        let ourMac = try getMac(
            senderIdentityKey: senderIdentityKey,
            receiverIdentityKey: receiverIdentityKey,
            macKey: macKey,
            message: content)

        guard ourMac.count == SignalMessage.macLength else {
            throw SignalError(.hmacError, "MAC length mismatch: \(mac.count) != \(SignalMessage.macLength)")
        }
        return ourMac == mac
    }

    /**
     Return the serialized version of the message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`, if the serialization fails
     */
    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .signal, data: try self.protoData())
    }
}

// MARK: Protocol Buffers

extension SignalMessage: ProtocolBufferEquivalent {

    /// Convert signal message to a ProtoBuf object
    var protoObject: Signal_SignalMessage {
        return Signal_SignalMessage.with {
            $0.ciphertext = self.cipherText
            $0.counter = self.counter
            $0.previousCounter = self.previousCounter
            $0.ratchetKey = senderRatchetKey.data
        }
    }

    /**
     Create a signal message from a ProtoBuf object.
     - parameter protoObject: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from protoObject: Signal_SignalMessage) throws {
        guard protoObject.hasCiphertext, protoObject.hasCounter,
            protoObject.hasRatchetKey, protoObject.hasPreviousCounter else {
                throw SignalError(.invalidProtoBuf, "Missing data in SignalMessage ProtoBuf object")
        }
        self.counter = protoObject.counter
        self.cipherText =  protoObject.ciphertext
        self.previousCounter = protoObject.previousCounter
        self.senderRatchetKey = try PublicKey(from: protoObject.ratchetKey)
        self.mac = Data()
    }

}

extension SignalMessage: ProtocolBufferSerializable {

    /**
     Serialize the message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public func protoData() throws -> Data {
        do {
            return try protoObject.serializedData() + mac
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SignalMessage: \(error)")
        }
    }

    /**
     Create a signal message from serialized data.
     - note: The types of errors thrown are:
     `invalidProtoBuf`, if data is missing or corrupt
     `invalidSignature`, if the signature length is incorrect
     `invalidMessage`, if the message is too short
     - parameter data: The serialized data
     - throws: `SignalError` errors
     */
    public init(from data: Data) throws {
        guard data.count > SignalMessage.macLength else {
            throw SignalError(.invalidMessage, "Invalid length of SignalMessage: \(data.count)")
        }
        let length = data.count - SignalMessage.macLength
        let newData = data[0..<length]

        let protoObject: Signal_SignalMessage
        do {
            protoObject = try Signal_SignalMessage(serializedData: newData)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create SignalMessage ProtoBuf object: \(error)")
        }
        try self.init(from: protoObject)
        self.mac = data.advanced(by: length)
    }
}

extension SignalMessage: Equatable {

    /**
     Compare two SignalMessages for equality.
     - note: Two messages are considered equal, if all of their variables match.
     - parameter lhs: The first message
     - parameter rhs: The second message
     - returns: `True`, if the messages are equal
    */
    public static func ==(lhs: SignalMessage, rhs: SignalMessage) -> Bool {
        guard lhs.counter == rhs.counter,
            lhs.previousCounter == rhs.previousCounter,
            lhs.cipherText == rhs.cipherText,
            lhs.mac == rhs.mac,
            lhs.senderRatchetKey == rhs.senderRatchetKey else {
                return false
        }
        return true
    }
}
