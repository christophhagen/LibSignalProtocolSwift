//
//  CipherTextMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 26.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

public enum CipherTextType: UInt8, CustomStringConvertible {
    case signal = 2
    case preKey = 3
    case senderKey = 4
    case senderKeyDistribution = 5

    public var description: String {
        switch self {
        case .signal: return "SignalMessage"
        case .preKey: return "PreKeyMessage"
        case .senderKey: return "SenderKeyMessage"
        case .senderKeyDistribution: return "SenderKeyDistributionMessage"
        }
    }
}

public struct CipherTextMessage {

    static let currentVersion: UInt8 = 3
    static let unsupportedVersion: UInt8 = 1

    public var type: CipherTextType

    public var data: Data
}
