//
//  DummyCryptoProvider.swift
//  SignalProtocolSwift-iOSTests
//
//  Created by User on 26.01.18.
//

import Foundation

/**
 This is a dummy implementation of the `SignalCryptoProvider` which will only
 throw errors. It's only intention is to serve as a dummy until an actual crypto
 provider is set for `SignalCrypto.provider`.
 */
struct DummyCryptoProvider: SignalCryptoProvider {

    func random(bytes: Int) throws -> Data {
        return try throwUnimplementedCryptoError()
    }

    func hmacSHA256(for message: Data, with salt: Data) throws -> Data {
        return try throwUnimplementedCryptoError()
    }

    func sha512(for message: Data) throws -> Data {
        return try throwUnimplementedCryptoError()
    }

    func encrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try throwUnimplementedCryptoError()
    }

    func decrypt(message: Data, with cipher: SignalEncryptionScheme, key: Data, iv: Data) throws -> Data {
        return try throwUnimplementedCryptoError()
    }

    private func throwUnimplementedCryptoError() throws -> Data {
        throw SignalError(.noCryptoProvider, "Set a crypto provider for SignalCrypto.provider")
    }

}
