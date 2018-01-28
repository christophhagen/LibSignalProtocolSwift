//
//  SessionPublicPreKey.swift
//  SignalProtocolSwift iOS
//
//  Created by User on 27.01.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation

/**
 A pre key used to esatblish a session. A unique pre key is used for
 each new session.
 */
public struct SessionPublicPreKey {

    /// The id of the pre key
    public let id: UInt32

    /// The key pair of the pre key
    public let key: PublicKey

    /**
     Create a public pre key from the components
     - parameter id: The pre key id
     - parameter keyPair: The public key of the pre key
     */
    init(id: UInt32, key: PublicKey) {
        self.id = id
        self.key = key
    }

    /**
     Create a public pre key from a complete pre key
     - parameter preKey: The complete pre key:
     */
    init(preKey: SessionPreKey) {
        self.id = preKey.id
        self.key = preKey.keyPair.publicKey
    }
}

// MARK: Protocol Buffers

extension SessionPublicPreKey {

    /// Convert the public pre key to a ProtoBuf object
    var object: Textsecure_PreKeyRecordStructure {
        return Textsecure_PreKeyRecordStructure.with {
            $0.id = self.id
            $0.publicKey = key.data
        }
    }

    /**
     Convert the public pre key to serialized data.
     - returns: The serialized record.
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SessionPublicPreKey: \(error)")
        }
    }

    /**
     Create a public pre key from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    init(from object: Textsecure_PreKeyRecordStructure) throws {
        guard object.hasID, object.hasPublicKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SessionPublicPreKey object")
        }
        self.id = object.id
        self.key = try PublicKey(from: object.publicKey)
    }

    /**
     Create a pre key from serialized data.
     - parameter data: The serialized record.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    public init(from data: Data) throws {
        let object: Textsecure_PreKeyRecordStructure
        do {
            object = try Textsecure_PreKeyRecordStructure(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not createSessionPreKey Protbuf object: \(error)")
        }
        try self.init(from: object)
    }
}
