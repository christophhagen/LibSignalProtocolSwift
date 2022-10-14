//
//  ProtocolBufferSerializable.swift
//  SignalProtocol iOS
//
//  Created by User on 13.02.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation

/**
 All types that conform to `Serializable` can be converted to and from data.
 */
public protocol ProtocolBufferSerializable {

    /**
     Convert the object to data.
     - throws: `SignalError` of type `invalidProtoBuf`
     - returns: The serialized object
     */
    func protoData() throws -> Data

    /**
     Create an object from its protobuf data
     - parameter protoData: The serialized data
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(from protoData: Data) throws

}
