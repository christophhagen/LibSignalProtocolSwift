//
//  SignalProtocolSwiftTests.swift
//  SignalProtocolSwiftTests
//
//  Created by User on 13.11.17.
//

import XCTest
@testable import SignalProtocolSwift

class SignalProtocolSwiftTests: XCTestCase {

    func testSHA512() {
        let input: [UInt8] = [0,1,2,3,4,5,6,7,8,9,10,11,12]
        let correctHash: [UInt8] = [182, 227, 10, 64, 22, 2, 148, 134,
                                    249, 32, 92, 93, 20, 19, 68, 248,
                                    133, 179, 222, 36, 104, 237, 251, 11,
                                    135, 5, 69, 241, 119, 92, 232, 37,
                                    151, 194, 164, 4, 98, 243, 133, 201,
                                    87, 121, 12, 32, 130, 45, 158, 146,
                                    14, 241, 174, 35, 8, 120, 214, 178,
                                    63, 34, 27, 1, 130, 135, 156, 204]

        guard let hash = try? SignalCrypto.sha512(for: input) else {
            XCTFail("Could not calculate hash")
            return
        }
        guard hash == correctHash else {
            XCTFail("Hash not correct")
            return
        }
    }

    func testHMAC() {
        let key: [UInt8] = [1,2,3,4,5]
        let message: [UInt8] = [2,3,4,5,6,7]
        let correctHMAC: [UInt8] = [108, 92, 22, 255, 237, 114, 145, 181,
                           183, 207, 58, 230, 250, 143, 45, 56,
                           112, 47, 95, 160, 56, 209, 128, 40,
                           15, 23, 185, 155, 173, 46, 81, 206]
        guard let hmac = try? SignalCrypto.hmacSHA256(for: message, with: key) else {
            XCTFail("Could not create HMAC")
            return
        }
        guard hmac == correctHMAC else {
            XCTFail("HMAC not correct")
            return
        }

    }

    func testEncrypt() {
        let key: [UInt8] = [166, 76, 22, 20, 4, 226, 125, 111,
                            149, 116, 198, 25, 65, 110, 128, 77,
                            192, 134, 194, 157, 53, 76, 46, 198,
                            186, 85, 233, 171, 147, 88, 27, 23]

        let iv: [UInt8] = [36, 142, 179, 171, 247, 31, 92, 64,
                           97, 195, 73, 47, 251, 1, 163, 182]

        let message: [UInt8] = [117, 112, 32, 116, 104, 101, 32, 112, 117, 110, 107, 115]

        let encryptedCBC: [UInt8] = [199, 122, 147, 81, 12, 156, 63, 30,
                                     102, 182, 96, 94, 151, 146, 65, 65]
        let encryptedCTR: [UInt8] = [153, 140, 109, 238, 184, 184,
                                     41, 27, 134, 251, 139, 57]

        process(message: message, key: key, iv: iv, with: .AES_CBCwithPKCS5, ciphertext: encryptedCBC)
        process(message: message, key: key, iv: iv, with: .AES_CTRnoPadding, ciphertext: encryptedCTR)
    }

    private func process(message: [UInt8], key: [UInt8], iv: [UInt8], with cipher: SignalEncryptionScheme, ciphertext: [UInt8]) {
        do {
            let cryptor = SignalCommonCrypto()
            let encrypted = try cryptor.encrypt(
                message: message, with: cipher, key: key, iv: iv)
            guard encrypted == ciphertext else {
                XCTFail("Invalid ciphertext")
                return
            }
            let decrypted = try cryptor.decrypt(
                message: encrypted, with: cipher, key: key, iv: iv)
            guard decrypted == message else {
                XCTFail("Invalid decrypted text")
                return
            }
        } catch {
            XCTFail("Could not encrypt/decrypt message")
            return
        }
    }

}
