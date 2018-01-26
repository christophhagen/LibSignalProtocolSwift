//
//  PendingPreKey.swift
//  SignalProtocolSwift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A pre key sent out as a pre key message
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

extension PendingPreKey {

    /**
     Create a pending pre key from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` error of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(serializedObject object: Textsecure_SessionStructure.PendingPreKey) throws {
        guard object.hasBaseKey, object.hasSignedPreKeyID else {
            throw SignalError(.invalidProtoBuf, "Missing data in object")
        }
        if object.hasPreKeyID {
            self.preKeyId = object.preKeyID
        }
        if object.signedPreKeyID < 0 {
            throw SignalError(.invalidProtoBuf, "Invalid SignedPreKey id \(object.signedPreKeyID)")
        }
        self.signedPreKeyId = UInt32(object.signedPreKeyID)
        self.baseKey = try PublicKey(from: object.baseKey)
    }

    /**
     Create a pending pre key from serialized data.
     - parameter data: The serialized data.
     - throws: `SignalError` error of type `invalidProtoBuf`, if data is missing or corrupt
     */
    init(from data: Data) throws {
        do {
            let object = try Textsecure_SessionStructure.PendingPreKey(serializedData: data)
            try self.init(serializedObject: object)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not deserialize PendingPreKey: \(error.localizedDescription)")
        }
    }

    /**
     Serialize a pending pre key for storage.
     - returns: The serialized data.
     - throws: `SignalError` error of type `invalidProtoBuf`, if the ProtoBuf object could not be serialized.
     */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize PendingPreKey: \(error.localizedDescription)")
        }
    }

    /// Create a ProtoBuf object for serialization.
    var object: Textsecure_SessionStructure.PendingPreKey {
        return Textsecure_SessionStructure.PendingPreKey.with {
            if let item = preKeyId {
                $0.preKeyID = item
            }
            $0.signedPreKeyID = Int32(self.signedPreKeyId)
            $0.baseKey = self.baseKey.data
        }
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
