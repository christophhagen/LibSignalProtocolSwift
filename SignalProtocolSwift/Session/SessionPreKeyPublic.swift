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
public struct SessionPreKeyPublic {

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
}

// MARK: Protocol Buffers

extension SessionPreKeyPublic {

    /// Convert the public pre key to a ProtoBuf object
    var object: Signal_PreKey.PublicPart {
        return Signal_PreKey.PublicPart.with {
            $0.id = self.id
            $0.key = key.data
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
    init(from object: Signal_PreKey.PublicPart) throws {
        guard object.hasID, object.hasKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SessionPublicPreKey object")
        }
        self.id = object.id
        self.key = try PublicKey(from: object.key)
    }

    /**
     Create a pre key from serialized data.
     - parameter data: The serialized record.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    public init(from data: Data) throws {
        let object: Signal_PreKey.PublicPart
        do {
            object = try Signal_PreKey.PublicPart(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not createSessionPreKey Protbuf object: \(error)")
        }
        try self.init(from: object)
    }
}
