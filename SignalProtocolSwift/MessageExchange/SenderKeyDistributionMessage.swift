//
//  SenderKeyDistributionMessage.swift
//  libsignal-protocol-swift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

public struct SenderKeyDistributionMessage {

    var id: UInt32

    var iteration: UInt32

    var chainKey: [UInt8]

    var signatureKey: PublicKey

    public func baseMessage() throws -> CipherTextMessage {
        return CipherTextMessage(type: .senderKeyDistribution, data: try self.data())
    }

    init(id: UInt32, iteration: UInt32, chainKey: [UInt8], signatureKey: PublicKey) {
        self.id = id
        self.iteration = iteration
        self.chainKey = chainKey
        self.signatureKey = signatureKey
    }
}

extension SenderKeyDistributionMessage {

    public func data() throws -> Data {
        let version = (CipherTextMessage.currentVersion << 4) | CipherTextMessage.currentVersion
        return try Data([version]) + object.serializedData()
    }
    
    var object: Textsecure_SenderKeyDistributionMessage {
        return Textsecure_SenderKeyDistributionMessage.with {
            $0.id = self.id
            $0.iteration = self.iteration
            $0.chainKey = Data(self.chainKey)
            $0.signingKey = self.signatureKey.data
        }
    }
    
    public init(from data: Data) throws {
        guard data.count > 1 else {
            throw SignalError(.invalidProtoBuf, "No data in SenderKeyDistributionMessage ProtoBuf data")
        }
        let version = (data[0] & 0xF0) >> 4
        if version < CipherTextMessage.currentVersion {
            throw SignalError(.legacyMessage, "Old message version \(version)")
        }
        if version > CipherTextMessage.currentVersion {
            throw SignalError(.invalidVersion, "Unknown version \(version)")
        }
        let object = try Textsecure_SenderKeyDistributionMessage(serializedData: data.advanced(by: 1))
        try self.init(from: object, version: version)
    }

    init(from object: Textsecure_SenderKeyDistributionMessage, version: UInt8) throws {
        guard object.hasID, object.hasIteration, object.hasChainKey, object.hasSigningKey else {
            throw SignalError(.invalidProtoBuf, "Missing data in SenderKeyDistributionMessage Protobuf object")
        }

        self.id = object.id
        self.iteration = object.iteration
        self.chainKey = [UInt8](object.chainKey)
        self.signatureKey = try PublicKey(from: object.signingKey)
    }
}

extension SenderKeyDistributionMessage: Equatable {
    public static func ==(lhs: SenderKeyDistributionMessage, rhs: SenderKeyDistributionMessage) -> Bool {
        return lhs.id == rhs.id &&
            lhs.iteration == rhs.iteration &&
            lhs.chainKey == rhs.chainKey &&
            lhs.signatureKey == rhs.signatureKey
    }
}
