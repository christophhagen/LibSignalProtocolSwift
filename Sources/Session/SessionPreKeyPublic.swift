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
struct SessionPreKeyPublic {

    /// The id of the pre key
    let id: UInt32

    /// The key pair of the pre key
    let key: PublicKey

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

extension SessionPreKeyPublic: ProtocolBufferEquivalent {

    /// Convert the public pre key to a ProtoBuf object
    var protoObject: Signal_PreKey.PublicPart {
        return Signal_PreKey.PublicPart.with {
            $0.id = self.id
            $0.key = key.data
        }
    }

    /**
     Create a public pre key from a ProtoBuf object.
     - parameter protoObject: The ProtoBuf object.
     - throws: `SignalError` of type `invalidProtoBuf` if data is corrupt or missing
     */
    init(from protoObject: Signal_PreKey.PublicPart) throws {
        guard protoObject.hasID, protoObject.hasKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SessionPublicPreKey object")
        }
        self.id = protoObject.id
        self.key = try PublicKey(from: protoObject.key)
    }
}
