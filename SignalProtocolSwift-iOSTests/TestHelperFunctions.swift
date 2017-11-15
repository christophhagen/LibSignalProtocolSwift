//
//  TestHelperFunctions.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 08.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

func shuffle<T>(_ buffer: inout [T]) {
    guard buffer.count > 1 else {
        return
    }
    for i in 0..<buffer.count-1 {
        let index = Int(arc4random_uniform(UInt32(buffer.count-i)))
        let a = buffer[i]
        buffer[i] = buffer[index]
        buffer[index] = a
    }
}
