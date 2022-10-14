//
//  CipherTextMessage.swift
//  SignalProtocolSwift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 The `CipherTextType` enum describes the different types of messages.
 */
public enum CipherTextType: UInt8, CustomStringConvertible {

    /// A 'normal' message in an established session
    case signal = 2
    /// A pre key message to establish a new session
    case preKey = 3
    /// A normal message in an established group session
    case senderKey = 4
    /// A distribution message to establish a new group session
    case senderKeyDistribution = 5

    /// A String representation of the type
    public var description: String {
        switch self {
        case .signal: return "SignalMessage"
        case .preKey: return "PreKeyMessage"
        case .senderKey: return "SenderKeyMessage"
        case .senderKeyDistribution: return "SenderKeyDistributionMessage"
        }
    }

    /// Encode the type into a string
    public var data: Data {
        return Data([self.rawValue])
    }

    /**
     Extract the `CipherTextType` from data.
     - note: Fails, if there is no data or an invalid type
     - parameter data: The data containing the version in the first byte
    */
    public init?(from data: Data) {
        guard data.count > 0 else {
            return nil
        }
        self.init(rawValue: data[0])
    }
}

/**
 A `CipherTextMessage` encapsulates an encrypted message and the type-
 */
public struct CipherTextMessage {

    /// The type of the message
    public var type: CipherTextType

    /// The encrypted message
    public var data: Data

    /**
     Create a message from the components.
     - parameter type: The message type
     - parameter data: The encrypted message
    */
    public init(type: CipherTextType, data: Data) {
        self.type = type
        self.data = data
    }
}

// MARK: Protocol Buffers

extension CipherTextMessage: ProtocolBufferSerializable {

    public func protoData() -> Data {
        return type.data + data
    }

    /**
     Create a `CipherTextMessage` from a serialized record.
     - parameter data: The serialized data.
     - throws: `SignalError` of type `invalidProtoBuf`, if data is corrupt or missing
    */
    public init(from data: Data) throws {
        guard data.count > 0 else {
            throw SignalError(.invalidProtoBuf, "No data to create CipherTextMessage")
        }
        guard let byte = CipherTextType(rawValue: data[0]) else {
            throw SignalError(.invalidProtoBuf, "Invalid type for CipherTextMessage")
        }
        self.type = byte
        self.data = data.advanced(by: 1)
    }
}
