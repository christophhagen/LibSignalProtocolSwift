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

    func random(bytes: Int) throws -> Data {
        var output = Data(count: bytes)
        for i in 0..<bytes {
            output[i] = testRandom
            testRandom = testRandom &+ 1
        }
        return output
    }

    func hmacSHA256(for message: Data, with salt: Data) throws -> Data {
        return try delegate.hmacSHA256(for: message, with: salt)
    }

    func sha512(for message: Data) throws -> Data {
        return try delegate.sha512(for: message)
    }

    func encrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try delegate.encrypt(message: message, with: cipher, key: key, iv: iv)
    }

    func decrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try delegate.decrypt(message: message, with: cipher, key: key, iv: iv)
    }
}
