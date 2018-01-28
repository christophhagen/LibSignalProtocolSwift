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
public final class Curve25519 {

    // MARK: Key Constants

    /// The length of the private and public key in bytes
    public static let keyLength = 32

    /// The length of a signature in bytes
    public static let signatureLength = 64

    /// The number of random bytes needed for signing
    public static let randomLength = 64

    // MARK: VRF Constants

    /// The length of a VRF signature in bytes
    public static let vrfSignatureLength = 96

    /// The number of random bytes needed for signing
    public static let vrfRandomLength = 32

    /// The length of the VRF verification output in bytes
    public static let vrfVerifyLength = 32

    // MARK: Public keys

    /**
     Generate a public key from a given private key.
     Fails if the key could not be generated.
     - note: Possible errors are:
     - `keyLength` if the private key is less than 32 byte
     - `basepointLength` if the basepoint is less than 32 byte
     - `curveError` if the curve donna implementation can't calculate the public key
     - parameter privateKey: The private key of the pair, 32 byte
     - parameter basepoint: The basepoint of the curve, 32 byte
     - returns: The public key (32 byte)
     - throws: `CurveError` errors
     */
    public static func publicKey(for privateKey: Data, basepoint: Data) throws -> Data {
        guard privateKey.count >= keyLength else {
            throw CurveError.keyLength(privateKey.count)
        }
        guard basepoint.count >= keyLength else {
            throw CurveError.basepointLength(basepoint.count)
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
            throw CurveError.curveError(result)
        }
        return key
    }

    // MARK: Signatures

    /**
     Calculate the signature for the given message.
     - note: Possible errors are:
     - `keyLength` if the private key is less than 32 byte
     - `randomLength` if the random data is less than 64 byte
     - `curveError` if the curve implementation can't calculate the signature
     - parameter message: The message to sign
     - parameter privateKey: The private key used for signing
     - parameter randomData: 64 byte of random data
     - returns: The signature of the message, `Curve25519.signatureLength` bytes
     - throws: `CurveError` errors
     */
    public static func signature(for message: Data, privateKey: Data, randomData: Data) throws -> Data {
        let length = message.count
        guard length > 0 else {
            throw CurveError.messageLength(length)
        }
        guard randomData.count >= randomLength else {
            throw CurveError.randomLength(randomData.count)
        }
        guard privateKey.count >= keyLength else {
            throw CurveError.keyLength(privateKey.count)
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
            throw CurveError.curveError(result)
        }
        return signature
    }

    /**
     Calculates a unique Curve25519 signature for the private key
     - note: Possible errors are:
     - `messageLength` if the message has length 0
     - `keyLength` if the private key is less than 32 byte
     - `randomLength` if the random data is less than 32 byte
     - `curveError` if the curve implementation can't calculate the signature
     - parameter message: The message to sign
     - parameter privateKey: The 32-byte private key to use for signing
     - parameter randomData: 32 byte of random data
     - returns: The 96-byte signature
     - throws: `CurveError` errors
     */
    public static func vrfSignature(for message: Data, privateKey: Data, randomData: Data) throws -> Data {
        let length = message.count
        guard length > 0 else {
            throw CurveError.messageLength(length)
        }
        guard randomData.count >= vrfRandomLength else {
            throw CurveError.randomLength(randomData.count)
        }
        guard privateKey.count >= keyLength else {
            throw CurveError.keyLength(privateKey.count)
        }

        var signature = Data(count: Curve25519.vrfSignatureLength)

        let result = message.withUnsafeBytes{ (messagePtr: UnsafePointer<UInt8>) in
            signature.withUnsafeMutableBytes { (sigPtr: UnsafeMutablePointer<UInt8>) in
                randomData.withUnsafeBytes{ (randomPtr: UnsafePointer<UInt8>) in
                    privateKey.withUnsafeBytes{ (keyPtr: UnsafePointer<UInt8>) in
                        generalized_xveddsa_25519_sign(sigPtr, keyPtr, messagePtr, UInt(length), randomPtr, nil, 0)
                    }
                }
            }
        }
        guard result == 0 else {
            throw CurveError.curveError(result)
        }
        return signature
    }

    // MARK: Verification

    /**
     Verify that the signature corresponds to the message.
     - parameter signature: The signature data
     - parameter message: The message for which the signature is checked
     - parameter publicKey: The 32-byte public key to verify the signature with
     - returns: `true`, if the signature is valid
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
     - note: Possible errors are:
     - `keyLength` if the public key is less than 32 byte
     - `signatureLength` if the signature data is not 96 byte
     - `curveError` if the curve implementation can't calculate the vrf output
     - parameter vrfSignature: The vrf signature data (96 byte)
     - parameter message: The message for which the signature is checked
     - parameter publicKey: The 32-byte public key to verify the signature with
     - returns: The vrf output (32 byte)
     - throws: `CurveError` errors
     */
    public static func verify(vrfSignature: Data, for message: Data, publicKey: Data) throws -> Data {
        guard vrfSignature.count == vrfSignatureLength else {
            throw CurveError.signatureLength(vrfSignature.count)
        }
        guard publicKey.count >= keyLength else {
            throw CurveError.keyLength(publicKey.count)
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
            throw CurveError.curveError(result)
        }
        return output
    }

    // MARK: Agreements

    /**
     Calculate the shared agreement between a private key and a public key.
     - note: Possible errors are:
     - `keyLength` if the public/private key is less than 32 byte
     - `curveError` if the curve implementation can't calculate the agreement
     - parameter privateKey: The private key for the agreement
     - parameter publicKey: The public key for the agreement
     - returns: The agreement data (32 byte)
     - throws: `CurveError` errors
     */
    public static func calculateAgreement(privateKey: Data, publicKey: Data) throws -> Data {
        guard publicKey.count >= keyLength else {
            throw CurveError.keyLength(publicKey.count)
        }
        guard privateKey.count >= keyLength else {
            throw CurveError.keyLength(privateKey.count)
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
            throw CurveError.curveError(result)
        }
        return sharedKey
    }
}




