//
//  Fingerprint.swift
//  libsignal-protocol-swift
//
//  Created by User on 10.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct Fingerprint {
    fileprivate static let version: UInt8 = 0
    fileprivate static let length = 30

    enum Version: UInt32 {
        case version0 = 0
        case version1 = 1
    }

    var displayable: DisplayableFingerprint
    var scannable: ScannableFingerprint
}


struct DisplayableFingerprint {
    var local: String
    var remote: String
    var displayText: String

    init(local: String, remote: String) {
        self.local = local
        self.remote = remote

        if local <= remote {
            self.displayText = local + remote
        } else {
            self.displayText = remote + local
        }
    }

    init(localFingerprint: Data, remoteFingerprint: Data) throws {
        let localString = try DisplayableFingerprint.createDisplayString(fingerprint: localFingerprint)
        let remoteString = try DisplayableFingerprint.createDisplayString(fingerprint: remoteFingerprint)
        self.init(local: localString, remote: remoteString)
    }

    private static func createDisplayString(fingerprint: Data) throws -> String {
        guard fingerprint.count >= Fingerprint.length else {
            throw SignalError.invalidLength
        }
        let data = [UInt8](fingerprint).map { UInt64($0) }
        var output = ""
        for i in stride(from: 0, to: 30, by: 5) {
            let chunk = (data[i] << 32) | (data[i+1] << 24)
            let chunk2 = (data[i+2] << 16) | (data[i+3] << 8) | data[i+4]
            let chunk3 = chunk | chunk2
            let val = Int(chunk3 % 100000)
            output += String(format: "%05d", val)
        }
        return output
    }
}


struct FingerprintGenerator {
    private var scannableVersion: Fingerprint.Version

    private var iterations: Int

    init(iterations: Int, scannableVersion: Fingerprint.Version) {
        self.iterations = iterations
        self.scannableVersion = scannableVersion
    }

    private func fingerprint(
        localStableIdentifier: String,
        localIdentity: Data,
        remoteStableIdentifier: String,
        remoteIdentity: Data) throws -> Fingerprint {

        let localFingerprint = try getFingerprint(identity: localIdentity, stableIdentifier: localStableIdentifier)
        let remoteFingerprint = try getFingerprint(identity: remoteIdentity, stableIdentifier: remoteStableIdentifier)
        let displayable = try DisplayableFingerprint(localFingerprint: localFingerprint, remoteFingerprint: remoteFingerprint)

        let scannable: ScannableFingerprint
        switch scannableVersion {
        case .version0:
            scannable = ScannableFingerprintV0(
                localStableIdentifier: localStableIdentifier,
                localFingerprint: localIdentity,
                remoteStableIdentifier: remoteStableIdentifier,
                remoteFingerprint: remoteIdentity)
        case .version1:
            scannable = try ScannableFingerprintV1(
                localFingerprint: localFingerprint,
                remoteFingerprint: remoteFingerprint)
        }
        return Fingerprint(displayable: displayable, scannable: scannable)
    }

    func fingerprint(
        localStableIdentifier: String,
        localIdentity: PublicKey,
        remoteStableIdentifier: String,
        remoteIdentity: PublicKey) throws -> Fingerprint {
        return try fingerprint(
            localStableIdentifier: localStableIdentifier,
            localIdentity: localIdentity.data,
            remoteStableIdentifier: remoteStableIdentifier,
            remoteIdentity: remoteIdentity.data)
    }

    func fingerprint(
        localStableIdentifier: String,
        localIdentityList: [PublicKey],
        remoteStableIdentifier: String,
        remoteIdentityList: [PublicKey]) throws -> Fingerprint {

        return try fingerprint(
            localStableIdentifier: localStableIdentifier,
            localIdentity: getLogicalKey(for: localIdentityList),
            remoteStableIdentifier: remoteStableIdentifier,
            remoteIdentity: getLogicalKey(for: remoteIdentityList))
    }

    /**
     Serialize the list of public keys by first sorting the keys and then
     concatenating the key data.
    */
    private func getLogicalKey(for keyList: [PublicKey]) -> Data {
        let list = keyList.sorted()

        return list.reduce(Data()) { (data: Data, key: PublicKey) -> Data in
            return data + key.data
        }
    }

    /**
     Calculate the fingerprint for identity data and identifier.
     - parameter identity: The serialized public key of the party
     - parameter stableIdentifier: The String description of the party
     - returns: The fingerprint data
     - throws `SignalError.invalidLength` if the SHA512 digest is too short
     */
    private func getFingerprint(identity: Data, stableIdentifier: String) throws -> Data {
        var hashBuffer = [0, Fingerprint.version] + identity + stableIdentifier.asByteArray
        for _ in 0..<iterations {
            hashBuffer = try SignalCrypto.sha512(for: hashBuffer + [UInt8](identity))
        }
        guard hashBuffer.count >= Fingerprint.length else {
            throw SignalError.invalidLength
        }
        return Data(hashBuffer)
    }
}
