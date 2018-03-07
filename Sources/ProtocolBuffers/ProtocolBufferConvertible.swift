//
//  ProtocolBufferConvertible.swift
//  SignalProtocol iOS
//
//  Created by User on 13.02.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation
import SwiftProtobuf

/**
 All types that conform to `ProtocolBufferConvertible` can be converted to and from a specific
 protobuf class.
 */
protocol ProtocolBufferConvertible: ProtocolBufferSerializable {

    /// The class type that the type can be converted to
    associatedtype ProtocolBufferClass: SwiftProtobuf.Message

    /**
     Convert to a protobuf object.
     - throws: `SignalError` of type `invalidProtoBuf`
     - returns: The protobuf object
     */
    func asProtoObject() throws -> ProtocolBufferClass

    /**
     Create an object from its protobuf equivalent
     - parameter protoObject: The protobuf object containing the data
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(from protoObject: ProtocolBufferClass) throws
}

extension ProtocolBufferConvertible {

    /**
     Convert the object to data.
     - throws: `SignalError` of type `invalidProtoBuf`
     - returns: The serialized object
     */
    public func protoData() throws -> Data {
        do {
            return try asProtoObject().serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf, "Serialization error: \(error)")
        }
    }

    /**
     Create an object from its protobuf data
     - parameter protoData: The serialized data
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    public init(from protoData: Data) throws {
        let protoObject: ProtocolBufferClass
        do {
            protoObject = try ProtocolBufferClass(serializedData: protoData)
        } catch {
            throw SignalError(.invalidProtoBuf, "Deserialization error: \(error)")
        }
        try self.init(from: protoObject)
    }
}
