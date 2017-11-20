//
//  HelperFunctions.swift
//  libsignal-protocol-swift
//
//  Created by User on 09.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Extension to serialize Int32
 */
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
     Create a `Int32` from a 4-byte array of UInt8
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

