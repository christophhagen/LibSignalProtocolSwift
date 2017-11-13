//
//  CipherTextMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

public enum CipherTextType: Int32 {
    case signal = 2
    case preKey = 3
    case senderKey = 4
    case senderKeyDistribution = 5
}

public struct CipherTextMessage {

    static let currentVersion: UInt8 = 3
    static let unsupportedVersion: UInt8 = 1

    public var type: CipherTextType

    public var data: Data
}
