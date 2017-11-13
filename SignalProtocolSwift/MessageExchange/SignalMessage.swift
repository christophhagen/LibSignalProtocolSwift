//
//  SignalMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


public struct SignalMessage {

    /// The length of the MAC for a message in bytes
    static let macLength = 8

    /// Return the serialized version of the message
    func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .signal, data: try self.data())
    }

    /// The message version
    var messageVersion: UInt8

    /// The public key of the sending ratchet
    var senderRatchetKey: PublicKey

    /// The current counter of the ratchet
    var counter: UInt32

    /// The previous counter of the ratchet
    var previousCounter: UInt32

    /// The encrypted text
    var cipherText: [UInt8]

    /// The mac of the message
    var mac: [UInt8]

    init(messageVersion: UInt8,
         macKey: [UInt8],
         senderRatchetKey: PublicKey,
         counter: UInt32,
         previousCounter: UInt32,
         cipherText: [UInt8],
         senderIdentityKey: PublicKey,
         receiverIdentityKey: PublicKey) throws {

        self.messageVersion = messageVersion
        self.senderRatchetKey = senderRatchetKey
        self.counter = counter
        self.previousCounter = previousCounter
        self.cipherText = cipherText
        self.mac = []
        self.mac = try getMac(senderIdentityKey: senderIdentityKey,
                         receiverIdentityKey: receiverIdentityKey,
                         macKey: macKey,
                         message: try self.data())
    }

    /**
     Calculate the MAC of the message. The length of the MAC is specified by `SignalMessage.macLength`
     */
    private func getMac(senderIdentityKey: PublicKey,
                receiverIdentityKey: PublicKey,
                macKey: [UInt8],
                message: Data) throws -> [UInt8] {

        let bytes = (messageVersion >= 3) ? senderIdentityKey.array + receiverIdentityKey.array : []
        let longMac: [UInt8] = try SignalCrypto.hmacSHA256(for: bytes +  [UInt8](message), with: macKey)

        guard longMac.count >= SignalMessage.macLength else {
            signalLog(level: .error, "MAC length invalid: Is \(SignalMessage.macLength), Maximum \(longMac.count)")
            throw SignalError.hmacError
        }

        return Array(longMac[0..<SignalMessage.macLength])
    }

    func verifyMac(senderIdentityKey: PublicKey,
                   receiverIdentityKey: PublicKey,
                   macKey: [UInt8]) -> Bool {

        guard let data = try? self.data() else {
            signalLog(level: .warning, "Could not serialize SignalMessage")
            return false
        }
        let length = data.count - SignalMessage.macLength
        let content = data[0..<length]

        guard let ourMac = try? getMac(
            senderIdentityKey: senderIdentityKey,
            receiverIdentityKey: receiverIdentityKey,
            macKey: macKey,
            message: content) else {
                signalLog(level: .warning, "Could not calculate mac for message")
                return false
        }

        guard ourMac.count == SignalMessage.macLength else {
            signalLog(level: .warning, "MAC length mismatch: \(mac.count) != \(SignalMessage.macLength)")
            return false
        }
        return ourMac == mac
    }

    static func isLegacyMessage(serialized: [UInt8]) -> Bool {
        guard serialized.count > 0 else {
            return false
        }
        return (serialized[0] & 0xF0) >> 4 <= CipherTextMessage.unsupportedVersion
    }
}

extension SignalMessage {

    public init(from data: Data) throws {
        guard data.count > SignalMessage.macLength else {
            signalLog(level: .warning, "Invalid length of SignalMessage: \(data.count)")
            throw SignalError.invalidMessage
        }
        let length = data.count - SignalMessage.macLength
        let mac =  [UInt8](data[length..<data.count])
        let newData = data[1..<length]
        let version = (data[0] & 0xF0) >> 4
        guard version > CipherTextMessage.unsupportedVersion,
            version <= CipherTextMessage.currentVersion else {
            signalLog(level: .warning, "Invalid version of SignalMessage: \(version)")
            throw SignalError.invalidVersion
        }
        let object = try Textsecure_SignalMessage(serializedData: newData)
        try self.init(from: object, version: version, mac: mac)
    }
        
    init(from object: Textsecure_SignalMessage, version: UInt8, mac: [UInt8]) throws {
        guard object.hasCiphertext, object.hasCounter,
            object.hasRatchetKey, object.hasPreviousCounter else {
                throw SignalError.invalidProtoBuf
        }
        self.counter = object.counter
        self.cipherText =  [UInt8](object.ciphertext)
        self.previousCounter = object.previousCounter
        self.senderRatchetKey = try PublicKey(from: object.ratchetKey)
        self.messageVersion = version
        self.mac = mac
    }

    public func data() throws -> Data {
        let version = messageVersion << 4 | CipherTextMessage.currentVersion
        return try Data([version]) + object().serializedData() + Data(mac)
    }
    
    func object() throws -> Textsecure_SignalMessage {
        return Textsecure_SignalMessage.with {
            $0.ciphertext = Data(self.cipherText)
            $0.counter = self.counter
            $0.previousCounter = self.previousCounter
            $0.ratchetKey = senderRatchetKey.data
        }
    }
}

extension SignalMessage: Equatable {

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
