//
//  SenderKeyDistributionMessage.swift
//  SignalProtocolSwift
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
        return CipherTextMessage(type: .senderKeyDistribution, data: try self.protoData())
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

extension SenderKeyDistributionMessage: ProtocolBufferEquivalent {

    /// Convert the distribution message to a ProtoBuf object
    var protoObject: Signal_SenderKeyDistributionMessage {
        return Signal_SenderKeyDistributionMessage.with {
            $0.id = self.id
            $0.iteration = self.iteration
            $0.chainKey = self.chainKey
            $0.signingKey = self.signatureKey.data
        }
    }

    /**
     Create a distribution message from a ProtoBuf object.
     - parameter protoObject: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from protoObject: Signal_SenderKeyDistributionMessage) throws {
        guard protoObject.hasID, protoObject.hasIteration, protoObject.hasChainKey, protoObject.hasSigningKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderKeyDistributionMessage Protobuf object")
        }

        self.id = protoObject.id
        self.iteration = protoObject.iteration
        self.chainKey = protoObject.chainKey
        self.signatureKey = try PublicKey(from: protoObject.signingKey)
    }
}
