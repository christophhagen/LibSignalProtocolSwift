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

    /// The message version
    var messageVersion: UInt8

    /// The public key of the sending ratchet
    var senderRatchetKey: PublicKey

    /// The current counter of the ratchet
    var counter: UInt32

    /// The counter of the previous ratchet
    var previousCounter: UInt32

    /// The encrypted text
    var cipherText: Data

    /// The mac of the message
    var mac: Data

    /**
     Create a SignalMessage from its components.
     - parameter messageVersion: The message version
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
    init(messageVersion: UInt8,
         macKey: Data,
         senderRatchetKey: PublicKey,
         counter: UInt32,
         previousCounter: UInt32,
         cipherText: Data,
         senderIdentityKey: PublicKey,
         receiverIdentityKey: PublicKey) throws {

        self.messageVersion = messageVersion
        self.senderRatchetKey = senderRatchetKey
        self.counter = counter
        self.previousCounter = previousCounter
        self.cipherText = cipherText
        self.mac = Data()
        self.mac = try getMac(senderIdentityKey: senderIdentityKey,
                              receiverIdentityKey: receiverIdentityKey,
                              macKey: macKey,
                              message: try self.data())
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

        let bytes = (messageVersion >= 3) ? senderIdentityKey.data + receiverIdentityKey.data : Data()
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

        let data = try self.data()
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
     Check if a message has an old version.
     - parameter serialized: The serialized SignalMessage
     - returns: `True`, if the message version is lower or equal to `CipherTextMessage.unsupportedVersion`
     */
    static func isLegacyMessage(serialized: Data) -> Bool {
        guard serialized.count > 0 else {
            return false
        }
        return (serialized[0] & 0xF0) >> 4 <= CipherTextMessage.unsupportedVersion
    }

    /**
     Return the serialized version of the message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`, if the serialization fails
     */
    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .signal, data: try self.data())
    }
}

// MARK: Protocol Buffers

extension SignalMessage {

    /**
     Serialize the message.
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public func data() throws -> Data {
        let version = messageVersion << 4 | CipherTextMessage.currentVersion
        do {
            return try Data([version]) + object.serializedData() + mac
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SignalMessage: \(error)")
        }
    }

    /// Convert signal message to a ProtoBuf object
    var object: Signal_SignalMessage {
        return Signal_SignalMessage.with {
            $0.ciphertext = self.cipherText
            $0.counter = self.counter
            $0.previousCounter = self.previousCounter
            $0.ratchetKey = senderRatchetKey.data
        }
    }
    
    /**
     Create a signal message from serialized data.
     - note: The types of errors thrown are:
     `invalidProtoBuf`, if data is missing or corrupt
     `invalidSignature`, if the signature length is incorrect
     `invalidVersion`, if the message version is not supported
     `invalidMessage`, if the message is too short
     - parameter data: The serialized data
     - throws: `SignalError` errors
     */
    public init(from data: Data) throws {
        guard data.count > SignalMessage.macLength else {
            throw SignalError(.invalidMessage, "Invalid length of SignalMessage: \(data.count)")
        }
        let length = data.count - SignalMessage.macLength
        let newData = data[1..<length]
        let mac = data.advanced(by: length)
        let version = (data[0] & 0xF0) >> 4
        guard version > CipherTextMessage.unsupportedVersion,
            version <= CipherTextMessage.currentVersion else {
                throw SignalError(.invalidVersion, "Invalid version of SignalMessage: \(version)")
        }
        let object: Signal_SignalMessage
        do {
            object = try Signal_SignalMessage(serializedData: newData)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create SignalMessage ProtoBuf object: \(error)")
        }
        try self.init(from: object, version: version, mac: mac)
    }

    /**
     Create a signal message from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from object: Signal_SignalMessage, version: UInt8, mac: Data) throws {
        guard object.hasCiphertext, object.hasCounter,
            object.hasRatchetKey, object.hasPreviousCounter else {
                throw SignalError(.invalidProtoBuf, "Missing data in SignalMessage ProtoBuf object")
        }
        self.counter = object.counter
        self.cipherText =  object.ciphertext
        self.previousCounter = object.previousCounter
        self.senderRatchetKey = try PublicKey(from: object.ratchetKey)
        self.messageVersion = version
        self.mac = mac
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
        guard lhs.messageVersion == rhs.messageVersion,
            lhs.counter == rhs.counter,
            lhs.previousCounter == rhs.previousCounter,
            lhs.cipherText == rhs.cipherText,
            lhs.mac == rhs.mac,
            lhs.senderRatchetKey == rhs.senderRatchetKey else {
                return false
        }
        return true
    }
}
