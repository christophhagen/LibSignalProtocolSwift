//
//  HelperFunctions.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Convert a void pointer to an instance of type T.

 - parameter caller: The void pointer to convert
 - returns: The instance, or nil, if the pointer is null
 */
func instance<T : AnyObject>(for caller: UnsafeMutableRawPointer?) -> T? {
    guard caller != nil else {
        return nil
    }
    return Unmanaged<T>.fromOpaque(caller!).takeUnretainedValue()
}

/**
 Create a void pointer from an instance.

 - returns: The void pointer to the instance
 */
func pointer<T : AnyObject>(obj : T) -> UnsafeMutableRawPointer {
    return UnsafeMutableRawPointer(Unmanaged.passUnretained(obj).toOpaque())
}

/**
 Create a string from a pointer to a UInt8 array.
 - parameter buffer: The pointer to the string
 - parameter length: The number of bytes of the String
 - returns: The String, if it could be created, or `nil`
 */
func stringFromBuffer(_ buffer: UnsafePointer<Int8>?, length: Int) -> String? {
    guard buffer != nil else {
        return nil
    }
    var data = Array(UnsafeBufferPointer(start: buffer, count: length))
    data.append(0)
    return String(cString: UnsafePointer(data))
}

/**
 Extension to serialize UInt32
 */
extension UInt32 {
    /**
     The value represented as an array of UInt8.
     */
    var arrayUInt8: [UInt8] {
        var _val = self
        return Array(withUnsafePointer(to: &_val) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<UInt32>.size) {
                UnsafeBufferPointer(start: $0, count: MemoryLayout<UInt32>.size)
            }
        })
    }

    /**
     Create a UIn32 from an Array of UInt8.
     */
    init(from array: [UInt8]) {
        self = array.withUnsafeBufferPointer {
            ($0.baseAddress!.withMemoryRebound(to: UInt32.self, capacity: 1) { $0 })
            }.pointee
    }
}

