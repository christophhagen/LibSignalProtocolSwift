//
//  TestFakeCryptoProvider.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 12.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import SignalProtocolSwift

class TestFakeCryptoProvider: SignalCryptoProvider {

    private let delegate = SignalCommonCrypto()

    private var testRandom: UInt8 = 0

    func random(bytes: Int) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: bytes)
        for i in 0..<bytes {
            output[i] = testRandom
            testRandom = testRandom &+ 1
        }
        return output
    }

    func hmacSHA256(for message: [UInt8], with salt: [UInt8]) throws -> [UInt8] {
        return try delegate.hmacSHA256(for: message, with: salt)
    }

    func sha512(for message: [UInt8]) throws -> [UInt8] {
        return try delegate.sha512(for: message)
    }

    func encrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        return try delegate.encrypt(message: message, with: cipher, key: key, iv: iv)
    }

    func decrypt(message: [UInt8], with cipher: SignalEncryptionScheme, key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        return try delegate.decrypt(message: message, with: cipher, key: key, iv: iv)
    }
}
