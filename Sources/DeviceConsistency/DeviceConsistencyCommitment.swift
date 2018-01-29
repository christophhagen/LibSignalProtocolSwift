//
//  DeviceConsistencyCommitment.swift
//  SignalProtocolSwift-iOS
//
//  Created by User on 18.11.17.
//

import Foundation

/**
 Create commitments that are hashes of the identity keys of different devices.
 These can be used to ensure that all identities are consistent across multiple
 devices.
 */
struct DeviceConsistencyCommitmentV0 {

    /// The version of the consistency implementation
    private static let codeVersion: UInt16 = 0

    /// An identifier used when hashing the identity keys
    private static let version = "DeviceConsistencyCommitment_V0".data(using: .utf8)!

    /// The generation of the message
    var generation: UInt32

    /// The hash of the public keys
    var serialized: Data

    /**
     Create a new commitment.
     - parameter generation: The version of the message
     - identityKeyList: The list of the identity keys of the participating devices
     - throws: `SignalError` errors thrown by the `sha512(for:)` function of the `SignalCryptoProvider`
    */
    init(generation: UInt32, identityKeyList: [PublicKey]) throws {
        let list = identityKeyList.sorted()
        var gen = generation
        let data = withUnsafePointer(to: &gen) { Data(bytes: $0, count: MemoryLayout<UInt32>.size) }

        var bytes = DeviceConsistencyCommitmentV0.version + data
        for item in list {
            bytes += item.data
        }
        self.serialized = try SignalCrypto.sha512(for: bytes)
        self.generation = generation
    }

    /**
     Generate a String which can be used to compare the consistency across multiple devices.
     The output is created by hashing the code version, hashed identity keys and device signatures, and then using parts of that hash as a String.
     - parameter signatureList: The list of device consistancy signatures received from other devices
     - throws: `SignalError` errors thrown by the `sha512(for:)` function of the `SignalCryptoProvider` or other errors
     - returns: The String created from the signatures, 6 characters long
    */
    func generateCode(for signatureList: [DeviceConsistencySignature]) throws -> String {
        let list = signatureList.sorted()

        let byte0 = UInt8(DeviceConsistencyCommitmentV0.codeVersion & 0x00FF)
        let byte1 = UInt8((DeviceConsistencyCommitmentV0.codeVersion & 0xFF00) >> 8)
        var bytes = Data([byte0, byte1]) + self.serialized

        for item in list {
            bytes +=  item.vrfOutput
        }

        let hash = try SignalCrypto.sha512(for: bytes)
        guard hash.count >= 10 else {
            throw SignalError(.digestError, "SHA512 hash is only \(hash.count) bytes")
        }
        let data = hash.map { UInt64($0) }
        let a1 = (data[0] << 32) | (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]
        let a2 = (data[5] << 32) | (data[6] << 24) | (data[7] << 16) | (data[8] << 8) | data[9]
        let b1 = Int(a1) % 100000
        let b2 = Int(a2) % 100000
        let longString = String(format: "%05d%05d", b1, b2)
        return String(longString.prefix(7))
    }
}
