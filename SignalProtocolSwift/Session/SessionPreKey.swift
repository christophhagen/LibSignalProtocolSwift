//
//  SessionPreKey.swift
//  SignalProtocolSwift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A pre key used to esatblish a session. A unique pre key is used for
 each new session.
 */
public struct SessionPreKey {

    /// The upper bound (inclusive) of the pre key id
    static let mediumMaxValue: UInt32 = 0xFFFFFF

    /// The id of the pre key
    var id: UInt32

    /// The key pair of the pre key
    var keyPair: KeyPair

    /**
     Create a pre key from the components
     - parameter id: The pre key id
     - parameter keyPair: The key pair of the pre key
    */
    init(id: UInt32, keyPair: KeyPair) {
        self.id = id
        self.keyPair = keyPair
    }

    /**
     Create a new pre key with the index.
     - note: Possible errors:
     - `curveError` if the public key could not be created.
     - `noRandomBytes`, if the crypto delegate could not provide random data
     - parameter index: The index to create the id
     - throws: `SignalError` errors
    */
    init(index: UInt32) throws {
        self.id = (index - 1) % (SessionPreKey.mediumMaxValue - 1) + 1
        self.keyPair = try KeyPair()
    }
}

// MARK: Protocol Buffers

extension SessionPreKey {

    /// Convert the pre key to a ProtoBuf object
    var object: Textsecure_PreKeyRecordStructure {
        return Textsecure_PreKeyRecordStructure.with {
            $0.id = self.id
            $0.publicKey = keyPair.publicKey.data
            $0.privateKey = keyPair.privateKey.data
        }
    }

    /**
     Convert the pre key to serialized data.
     - returns: The serialized record.
     - throws: `SignalError` of type `invalidProtoBuf`
    */
    public func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Could not serialize SessionPreKey: \(error)")
        }
    }

    /**
     Create a pre key from a ProtoBuf object.
     - parameter object: The ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    init(from object: Textsecure_PreKeyRecordStructure) throws {
        guard object.hasID, object.hasPublicKey, object.hasPrivateKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SessionPreKey object")
        }
        self.id = object.id
        self.keyPair = KeyPair(
            publicKey: try PublicKey(from: object.publicKey),
            privateKey: try PrivateKey(from: object.privateKey))
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
