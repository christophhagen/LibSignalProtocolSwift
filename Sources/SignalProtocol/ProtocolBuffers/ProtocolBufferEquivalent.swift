//
//  ProtocolBufferEquivalent.swift
//  SignalProtocol iOS
//
//  Created by User on 13.02.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation

/**
 All types that conform to `ProtocolBufferConvertible` can be converted to and from a specific
 protobuf class.
 */
protocol ProtocolBufferEquivalent: ProtocolBufferConvertible {

    /// The object converted to a protobuf object.
    var protoObject: ProtocolBufferClass { get }
}

/**
 Default implementation to provide the `object()` function for all types that conform to `ProtocolBufferEquivalent`.
 */
extension ProtocolBufferEquivalent {

    /**
     Convert the object to a protobuf object.
     - returns: The protobuf object
     */
    func asProtoObject() -> ProtocolBufferClass {
        return protoObject
    }
}
