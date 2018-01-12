//
//  SenderKeyDistributionMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 `SenderKeyDistributionMessage`s are used to establish group sessions.
 */
public struct SenderKeyDistributionMessage {

    /// The id of the message
    var id: UInt32

    /// The current chain iteration of the message
    var iteration: UInt32

    /// The chain key used for the message
    var chainKey: Data

    /// The signature key used for signing the message
    var signatureKey: PublicKey

    /**
     Create a serialized message from the distribution message
     - returns: The serialized message
     - throws: `SignalError` of type `invalidProtoBuf` if the serialization fails
    */
    public func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .senderKeyDistribution, data: try self.data())
    }

    /**
     Create a distribution message.
     - parameter id: The id of the message
     - parameter iteration: The current chain iteration of the message
     - parameter chainKey: The chain key used for the message
     - parameter signatureKey: The signature key used for signing the message
    */
    init(id: UInt32, iteration: UInt32, chainKey: Data, signatureKey: PublicKey) {
        self.id = id
        self.iteration = iteration
        self.chainKey = chainKey
        self.signatureKey = signatureKey
    }
}

// MARK: Protocol Equatable

extension SenderKeyDistributionMessage: Equatable {

    /**
     Compare two distribution messages.
     - parameter lhs: The first message.
     - parameter rhs: The second message.
     - returns: `True` if the messages match.
    */
    public static func ==(lhs: SenderKeyDistributionMessage, rhs: SenderKeyDistributionMessage) -> Bool {
        return lhs.id == rhs.id &&
            lhs.iteration == rhs.iteration &&
            lhs.chainKey == rhs.chainKey &&
            lhs.signatureKey == rhs.signatureKey
    }
}

// MARK: Protocol buffers

extension SenderKeyDistributionMessage {

    /**
     Convert the distribution message to serialized data.
     - returns: Serialized data
     - throws: `SignalError` of type `invalidProtoBuf`, if the serialization fails
    */
    public func data() throws -> Data {
        let version = (CipherTextMessage.currentVersion << 4) | CipherTextMessage.currentVersion
        do {
            return try Data([version]) + object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SenderKeyDistributionMessage: \(error)")
        }
    }

    /// Convert the distribution message to a ProtoBuf object
    var object: Textsecure_SenderKeyDistributionMessage {
        return Textsecure_SenderKeyDistributionMessage.with {
            $0.id = self.id
            $0.iteration = self.iteration
            $0.chainKey = self.chainKey
            $0.signingKey = self.signatureKey.data
        }
    }

    /**
     Create a distribution message from serialized data.
     - note: The types of errors thrown are:
     - `invalidProtoBuf`, if data is missing or corrupt
     - `legacyMessage`, if the message version is older than the current version
     - `invalidVersion`, if the message version is newer than the current version
     - parameter data: The serialized data
     - throws: `SignalError` errors
    */
    public init(from data: Data) throws {
        guard data.count > 1 else {
            throw SignalError(.invalidProtoBuf, "No data in SenderKeyDistributionMessage ProtoBuf data")
        }
        let version = (data[0] & 0xF0) >> 4
        if version < CipherTextMessage.currentVersion {
            throw SignalError(.legacyMessage, "Old message version \(version)")
        }
        if version > CipherTextMessage.currentVersion {
            throw SignalError(.invalidVersion, "Unknown version \(version)")
        }
        let object: Textsecure_SenderKeyDistributionMessage
        do {
            object = try Textsecure_SenderKeyDistributionMessage(serializedData: data.advanced(by: 1))
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not create distribution message object: \(error)")
        }
        try self.init(from: object, version: version)
    }

    /**
     Create a distribution message from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from object: Textsecure_SenderKeyDistributionMessage, version: UInt8) throws {
        guard object.hasID, object.hasIteration, object.hasChainKey, object.hasSigningKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderKeyDistributionMessage Protobuf object")
        }

        self.id = object.id
        self.iteration = object.iteration
        self.chainKey = object.chainKey
        self.signatureKey = try PublicKey(from: object.signingKey)
    }
}
