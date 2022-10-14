//
//  PendingPreKey.swift
//  SignalProtocolSwift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A pre key sent out as a pre key message, until a message is received from the other party
 */
struct PendingPreKey {

    /// The id of the pre key, if one was used
    var preKeyId: UInt32?

    /// The id of the signed pre key
    var signedPreKeyId: UInt32

    /// The base key used for the outgoing pre key message
    var baseKey: PublicKey

}

// MARK: Protocol Buffers

extension PendingPreKey: ProtocolBufferEquivalent {

    /// Create a ProtoBuf object for serialization.
    var protoObject: Signal_Session.PendingPreKey {
        return Signal_Session.PendingPreKey.with {
            if let item = preKeyId {
                $0.preKeyID = item
            }
            $0.signedPreKeyID = Int32(self.signedPreKeyId)
            $0.baseKey = self.baseKey.data
        }
    }

    /**
     Create a pending pre key from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` error of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from protoObject: Signal_Session.PendingPreKey) throws {
        guard protoObject.hasBaseKey, protoObject.hasSignedPreKeyID else {
            throw SignalError(.invalidProtoBuf, "Missing data in object")
        }
        if protoObject.hasPreKeyID {
            self.preKeyId = protoObject.preKeyID
        }
        if protoObject.signedPreKeyID < 0 {
            throw SignalError(.invalidProtoBuf, "Invalid SignedPreKey id \(protoObject.signedPreKeyID)")
        }
        self.signedPreKeyId = UInt32(protoObject.signedPreKeyID)
        self.baseKey = try PublicKey(from: protoObject.baseKey)
    }
}

// MARK: Protocol Equatable

extension PendingPreKey: Equatable {

    /**
     Compare two pending pre keys for equality.
     - parameters lhs: The first pre key
     - parameters rhs: The second pre key
     - returns: `True`, if the pre keys match
     */
    static func ==(lhs: PendingPreKey, rhs: PendingPreKey) -> Bool {
        return lhs.preKeyId == rhs.preKeyId &&
            lhs.signedPreKeyId == rhs.signedPreKeyId &&
            lhs.baseKey == rhs.baseKey
    }
}
