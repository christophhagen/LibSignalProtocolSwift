//
//  RatchetMessageKeys.swift
//  libsignal-protocol-swift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


struct RatchetMessageKeys {

    static let cipherKeyLength = 32
    static let macKeyLength = 32
    static let ivLength = 16
    static let derivedMessageSecretsSize = cipherKeyLength + macKeyLength + ivLength

    var cipherKey: [UInt8]

    var macKey: [UInt8]

    var iv: [UInt8]
    
    var counter: UInt32

    init(cipher: [UInt8], mac: [UInt8], iv: [UInt8], counter: UInt32) throws {
        guard cipher.count == RatchetMessageKeys.cipherKeyLength else {
            signalLog(level: .error, "Invalid cipher key length \(cipher.count)")
            throw SignalError.invalidLength
        }
        guard mac.count == RatchetMessageKeys.macKeyLength else {
            signalLog(level: .error, "Invalid mac key length \(mac.count)")
            throw SignalError.invalidLength
        }
        guard iv.count == RatchetMessageKeys.ivLength else {
            signalLog(level: .error, "Invalid iv length \(iv.count)")
            throw SignalError.invalidLength
        }
        self.cipherKey = cipher
        self.macKey = mac
        self.iv = iv
        self.counter = counter
    }

    init(from bytes: [UInt8]) throws {
        guard bytes.count == RatchetMessageKeys.derivedMessageSecretsSize + 4 else {
            throw SignalError.invalidLength
        }
        self.cipherKey = Array(bytes[0..<RatchetMessageKeys.cipherKeyLength])
        let length2 = RatchetMessageKeys.cipherKeyLength + RatchetMessageKeys.macKeyLength
        self.macKey = Array(bytes[RatchetMessageKeys.cipherKeyLength..<length2])
        self.iv = Array(bytes[length2..<RatchetMessageKeys.derivedMessageSecretsSize])
        self.counter = UInt32(from: Array(bytes[RatchetMessageKeys.derivedMessageSecretsSize..<bytes.count]))!
    }
}

extension RatchetMessageKeys {
    
    init(from object: Textsecure_SessionStructure.Chain.MessageKey) {
        self.counter = object.index
        self.cipherKey = [UInt8](object.cipherKey)
        self.iv = [UInt8](object.iv)
        self.macKey = [UInt8](object.macKey)
    }
    
    init(from data: Data) throws {
        let object = try Textsecure_SessionStructure.Chain.MessageKey(serializedData: data)
        self.init(from: object)
    }
    
    func data() throws -> Data {
        return try object.serializedData()
    }
    
    var object: Textsecure_SessionStructure.Chain.MessageKey {
        return Textsecure_SessionStructure.Chain.MessageKey.with {
            $0.index = self.counter
            $0.cipherKey = Data(self.cipherKey)
            $0.iv = Data(self.iv)
            $0.macKey = Data(self.macKey)
        }
    }

}

extension RatchetMessageKeys: Equatable {
    static func ==(lhs: RatchetMessageKeys, rhs: RatchetMessageKeys) -> Bool {
        return lhs.counter == rhs.counter &&
            lhs.cipherKey == rhs.cipherKey &&
            lhs.iv == rhs.iv &&
            lhs.macKey == rhs.macKey
    }
}
