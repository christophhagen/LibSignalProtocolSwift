//
//  HelperFunctions.swift
//  libsignal-protocol-swift
//
//  Created by User on 09.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


public struct SignalAddress {

    var name: String

    var deviceId: Int32
}

extension SignalAddress: Equatable {
    public static func ==(lhs: SignalAddress, rhs: SignalAddress) -> Bool {
        return lhs.name == rhs.name && lhs.deviceId == rhs.deviceId
    }
}

extension SignalAddress: Hashable {
    public var hashValue: Int {
        return name.hashValue + deviceId.hashValue
    }
}

extension SignalAddress: CustomStringConvertible {
    public var description: String {
        return "SignalAddress(\(name),\(deviceId))"
    }
}



/*
 * A representation of a (group + sender + device) tuple
 */
public struct SignalSenderKeyName {
    var groupId: String
    var sender: SignalAddress
}

extension SignalSenderKeyName: Equatable {
    public static func ==(lhs: SignalSenderKeyName, rhs: SignalSenderKeyName) -> Bool {
        return lhs.groupId == rhs.groupId && lhs.sender == rhs.sender
    }
}

extension SignalSenderKeyName: Hashable {
    public var hashValue: Int {
        return sender.hashValue + groupId.hashValue
    }
}

extension Int32 {
    
    /// Represent an `Int32` as a 4-byte array of UInt8
    var asByteArray: [UInt8] {
        var val = self
        return Array(withUnsafePointer(to: &val) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<Int32>.size) {
                UnsafeBufferPointer(start: $0, count: MemoryLayout<Int32>.size)
            }
        })
    }
    
    /**
     Create a `UInt32` from a 4-byte array of UInt8
     - parameter bytes: The 4-byte record
     */
    init?(from bytes: [UInt8]) {
        guard bytes.count == MemoryLayout<Int32>.size else {
            return nil
        }
        self = bytes.withUnsafeBufferPointer {
            ($0.baseAddress!.withMemoryRebound(to: Int32.self, capacity: 1) { $0 })
            }.pointee
    }
}

/**
 Extension to serialize UInt32
 */
extension UInt32 {
    
    /// Represent a `UInt32` as a 4-byte array of UInt8
    var asByteArray: [UInt8] {
        var val = self
        return Array(withUnsafePointer(to: &val) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<UInt32>.size) {
                UnsafeBufferPointer(start: $0, count: MemoryLayout<UInt32>.size)
            }
        })
    }
    
    /**
     Create a `UInt32` from a 4-byte array of UInt8
     - parameter bytes: The 4-byte record
     */
    init?(from bytes: [UInt8]) {
        guard bytes.count == MemoryLayout<UInt32>.size else {
            return nil
        }
        self = bytes.withUnsafeBufferPointer {
            ($0.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 1) { $0 })
            }.pointee
    }
}

extension String {

    var asByteArray: [UInt8] {
        return [UInt8](self.utf8)
    }
}

