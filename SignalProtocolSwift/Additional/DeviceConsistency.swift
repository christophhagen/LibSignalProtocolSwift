//
//  DeviceConsistency.swift
//  libsignal-protocol-swift
//
//  Created by User on 08.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct DeviceConsistencySignature {
    var signature: Data
    var vrfOutput: Data

    init(signature: Data, vrfOutput: Data) {
        self.signature = signature
        self.vrfOutput = vrfOutput
    }
}

extension DeviceConsistencySignature: Comparable {
    static func <(lhs: DeviceConsistencySignature, rhs: DeviceConsistencySignature) -> Bool {
        guard lhs.vrfOutput.count == rhs.vrfOutput.count else {
            return lhs.vrfOutput.count < rhs.vrfOutput.count
        }
        for i in 0..<lhs.vrfOutput.count {
            if lhs.vrfOutput[i] != rhs.vrfOutput[i] {
                return lhs.vrfOutput[i] < rhs.vrfOutput[i]
            }
        }
        return false
    }

    static func ==(lhs: DeviceConsistencySignature, rhs: DeviceConsistencySignature) -> Bool {
        return lhs.vrfOutput == rhs.vrfOutput
    }
}

struct DeviceConsistencyCommitment {
    private static let codeVersion: UInt16 = 0
    private static let version = "DeviceConsistencyCommitment_V0".asByteArray
    var generation: UInt32
    var serialized: Data

    init(generation: UInt32, identityKeyList: [PublicKey]) throws {
        let list = identityKeyList.sorted()
        var bytes = DeviceConsistencyCommitment.version
        bytes += generation.asByteArray
        for item in list {
            bytes += item.array
        }
        self.serialized = Data(try SignalCrypto.sha512(for: bytes))
        self.generation = generation
    }

    func generateCode(for signatureList: [DeviceConsistencySignature]) throws -> String {
        let list = signatureList.sorted()

        let byte0 = UInt8(DeviceConsistencyCommitment.codeVersion & 0x00FF)
        let byte1 = UInt8((DeviceConsistencyCommitment.codeVersion & 0xFF00) >> 8)
        var bytes = [byte0, byte1] +  [UInt8](self.serialized)

        for item in list {
            bytes +=  [UInt8](item.vrfOutput)
        }

        let hash = try SignalCrypto.sha512(for: bytes)
        guard hash.count >= 10 else {
            throw SignalError.unknown
        }
        let data = hash.map{ UInt64($0) }
        let a1 = (data[0] << 32) | (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]
        let a2 = (data[5] << 32) | (data[6] << 24) | (data[7] << 16) | (data[8] << 8) | data[9]
        let b1 = Int(a1) % 100000
        let b2 = Int(a2) % 100000
        let longString = String(format: "%05d%05d", b1, b2).asByteArray
        var stringBytes = Array(longString[0..<7])
        stringBytes[6] = 0
        guard let result = String.init(bytes: stringBytes, encoding: .utf8) else {
            throw SignalError.unknown
        }
        return result
    }
}

struct DeviceConsistencyMessage {
    var signature: DeviceConsistencySignature
    var generation: UInt32

    init(commitment: DeviceConsistencyCommitment, identitykeyPair: KeyPair) throws {

        /* Calculate VRF signature */
        let signature = try identitykeyPair.privateKey.signVRF(message: commitment.serialized)

        /* Verify VRF signature */
        let vrfOutput = try identitykeyPair.publicKey.verify(vrfSignature: signature, for: commitment.serialized)

        /* Create and assign the signature */
        self.signature = DeviceConsistencySignature(signature: signature, vrfOutput: vrfOutput)
        self.generation = commitment.generation
    }

    func data() throws -> Data {
        return try object.serializedData()
    }

    var object: Textsecure_DeviceConsistencyCodeMessage {
        return Textsecure_DeviceConsistencyCodeMessage.with {
            $0.generation = self.generation
            $0.signature = self.signature.signature
        }
    }

    init(from data: Data, commitment: DeviceConsistencyCommitment, identityKey: PublicKey) throws {
        let object = try Textsecure_DeviceConsistencyCodeMessage(serializedData: data)
        try self.init(from: object, commitment: commitment, identityKey: identityKey)
    }

    init(from object: Textsecure_DeviceConsistencyCodeMessage, commitment: DeviceConsistencyCommitment, identityKey: PublicKey) throws {
        guard object.hasSignature, object.hasGeneration else {
            throw SignalError.invalidProtoBuf
        }

        /* Verify VRF signature */
        let vrfOutput = try identityKey.verify(vrfSignature: object.signature, for: commitment.serialized)

        /* Assign the message fields */
        self.generation = object.generation
        self.signature = DeviceConsistencySignature(signature: object.signature, vrfOutput: vrfOutput)
    }
}
