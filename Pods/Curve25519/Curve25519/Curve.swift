//
//  Empty.swift
//  Curve25519
//
//  Created by User on 27.01.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation

/**
 Curve25519 provides access to elliptic curve signature, agreement and verification functions.
 */
public struct Curve25519 {

    /// The length of the private and public key in bytes
    public static let keyLength = 32

    /// The length of a signature in bytes
    public static let signatureLength = 64

    /// The length of a VRF signature in bytes
    public static let vrfSignatureLength = 96

    /// The length of the VRF verification output in bytes
    static let vrfVerifyLength = 32

    // MARK: Public keys

    /**
     Generate a public key from a given private key.
     Fails if the key could not be generated.
     - parameter privateKey: The private key of the pair, 32 byte
     - parameter basepoint: The basepoint of the curve, 32 byte
     - returns: The public key (32 byte), or nil on failure
     */
    public static func publicKey(for privateKey: Data, basepoint: Data) -> Data? {
        guard privateKey.count >= keyLength,
            basepoint.count >= keyLength else {
            return nil
        }

        var key = Data(count: keyLength)
        let result: Int32 = key.withUnsafeMutableBytes { keyPtr in
            privateKey.withUnsafeBytes { privPtr in
                basepoint.withUnsafeBytes {
                    curve25519_donna(keyPtr, privPtr, $0)
                }
            }
        }
        
        guard result == 0 else {
            return nil
        }
        return key
    }

    // MARK: Signatures

    /**
     Calculate the signature for the given message.
     - parameter message: The message to sign
     - parameter privateKey: The private key used for signing
     - parameter randomData: 64 byte of random data
     - returns: The signature of the message, `KeyPair.signatureLength` bytes, or nil on failure
     */
    public static func signature(for message: Data, privateKey: Data, randomData: Data) -> Data? {
        let length = message.count
        guard length > 0,
            randomData.count >= signatureLength,
            privateKey.count >= keyLength else {
            return nil
        }
        var signature = Data(count: signatureLength)
        let result = randomData.withUnsafeBytes{ (randomPtr: UnsafePointer<UInt8>) in
            signature.withUnsafeMutableBytes { (sigPtr: UnsafeMutablePointer<UInt8>) in
                privateKey.withUnsafeBytes{ (keyPtr: UnsafePointer<UInt8>) in
                    message.withUnsafeBytes { (messPtr: UnsafePointer<UInt8>) in
                        curve25519_sign(sigPtr, keyPtr, messPtr, UInt(length), randomPtr)
                    }
                }
            }
        }
        guard result == 0 else {
            return nil
        }
        return signature
    }

    /**
     Calculates a unique Curve25519 signature for the private key
     - parameter message: The message to sign
     - parameter privateKey: The 32-byte private key to use for signing
     - parameter randomData: 64 byte of random data
     - returns: The 96-byte signature on success, nil on failure
     */
    public static func vrfSignature(for message: Data, privateKey: Data, randomData: Data) -> Data? {
        let length = UInt(message.count)
        guard length > 0,
            randomData.count >= signatureLength,
            privateKey.count >= keyLength else {
                return nil
        }

        var signature = Data(count: Curve25519.vrfSignatureLength)

        let result = message.withUnsafeBytes{ (messagePtr: UnsafePointer<UInt8>) in
            signature.withUnsafeMutableBytes { (sigPtr: UnsafeMutablePointer<UInt8>) in
                randomData.withUnsafeBytes{ (randomPtr: UnsafePointer<UInt8>) in
                    privateKey.withUnsafeBytes{ (keyPtr: UnsafePointer<UInt8>) in
                        generalized_xveddsa_25519_sign(sigPtr, keyPtr, messagePtr, length, randomPtr, nil, 0)
                    }
                }
            }
        }
        guard result == 0 else {
            return nil
        }
        return signature
    }

    // MARK: Verification

    /**
     Verify that the signature corresponds to the message.
     - parameter signature: The signature data
     - parameter message: The message for which the signature is checked
     - parameter publicKey: The public key to verify the signature with
     - returns: True, if the signature is valid
     */
    public static func verify(signature: Data, for message: Data, publicKey: Data) -> Bool {
        guard signature.count == signatureLength,
            publicKey.count >= keyLength else {
            return false
        }
        let result = signature.withUnsafeBytes { signaturePtr in
            publicKey.withUnsafeBytes { keyPtr in
                message.withUnsafeBytes { messagePtr in
                    curve25519_verify(signaturePtr, keyPtr, messagePtr, UInt(message.count))
                }
            }
        }
        return result == 0
    }

    /**
     Verify that the vrf signature corresponds to the message.
     - parameter signature: The vrf signature data
     - parameter message: The message for which the signature is checked
     - parameter publicKey: The public key to verify the signature with
     - returns: The vrf output, or nil on failure
     */
    public static func verify(vrfSignature: Data, for message: Data, publicKey: Data) -> Data? {
        guard vrfSignature.count == vrfSignatureLength,
            publicKey.count >= keyLength else {
            return nil
        }

        var output = Data(count: vrfVerifyLength)
        let result = publicKey.withUnsafeBytes { keyPtr in
            message.withUnsafeBytes { messagePtr in
                vrfSignature.withUnsafeBytes { vrfPtr in
                    output.withUnsafeMutableBytes { outputPtr in
                        generalized_xveddsa_25519_verify(outputPtr, vrfPtr, keyPtr, messagePtr, UInt(message.count), nil, 0)
                    }
                }
            }
        }
        guard result == 0 else {
            return nil
        }
        return output
    }

    // MARK: Agreements

    /**
     Calculate the shared agreement between a private key a public key.
     - note: The returned data has a length of `KeyPair.keyLength` byte.
     - parameter privateKey: The private key for the agreement
     - parameter publicKey: The public key for the agreement
     - returns: The agreement data, or `nil` on failure
     */
    public static func calculateAgreement(privateKey: Data, publicKey: Data) -> Data? {
        guard publicKey.count >= keyLength,
            privateKey.count >= keyLength else {
            return nil
        }

        var sharedKey = Data(count: keyLength)
        let result: Int32 = sharedKey.withUnsafeMutableBytes { sharedKeyPtr in
            privateKey.withUnsafeBytes { dataPtr in
                publicKey.withUnsafeBytes { keyPtr in
                    curve25519_donna(sharedKeyPtr, dataPtr, keyPtr)
                }
            }
        }
        guard result == 0 else {
            return nil
        }
        return sharedKey
    }
}




