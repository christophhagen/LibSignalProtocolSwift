//
//  Fingerprint.swift
//  libsignal-protocol-swift
//
//  Created by User on 10.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A fingerprint can be used to ensure that the identities of a communication channel
 match, and to detect MITM attacks.
 */
public struct Fingerprint {

    /// The version of the fingerprint
    static let version: UInt8 = 0

    /// The length of a fingerprint
    static let length = 30

    /// The version of the scannable fingerprint
    enum Version: UInt32 {
        case version0 = 0
        case version1 = 1
    }

    var displayable: DisplayableFingerprint

    var scannable: ScannableFingerprint

    init(iterations: Int,
         scannableVersion: Version,
         localStableIdentifier: String,
         localIdentity: Data,
         remoteStableIdentifier: String,
         remoteIdentity: Data) throws {

        let localFingerprint = try getFingerprint(
            identity: localIdentity,
            stableIdentifier: localStableIdentifier,
            iterations: iterations)
        let remoteFingerprint = try getFingerprint(
            identity: remoteIdentity,
            stableIdentifier: remoteStableIdentifier,
            iterations: iterations)
        self.displayable = try DisplayableFingerprint(localFingerprint: localFingerprint, remoteFingerprint: remoteFingerprint)

        switch scannableVersion {
        case .version0:
            self.scannable = ScannableFingerprintV0(
                localStableIdentifier: localStableIdentifier,
                localFingerprint: localIdentity,
                remoteStableIdentifier: remoteStableIdentifier,
                remoteFingerprint: remoteIdentity)
        case .version1:
            self.scannable = try ScannableFingerprintV1(
                localFingerprint: localFingerprint,
                remoteFingerprint: remoteFingerprint)
        }
    }

    init(iterations: Int,
         scannableVersion: Fingerprint.Version,
         localStableIdentifier: String,
         localIdentity: PublicKey,
         remoteStableIdentifier: String,
         remoteIdentity: PublicKey) throws {
        try self.init(
            iterations: iterations,
            scannableVersion: scannableVersion,
            localStableIdentifier: localStableIdentifier,
            localIdentity: localIdentity.data,
            remoteStableIdentifier: remoteStableIdentifier,
            remoteIdentity: remoteIdentity.data)
    }

    init(iterations: Int,
         scannableVersion: Fingerprint.Version,
         localStableIdentifier: String,
         localIdentityList: [PublicKey],
         remoteStableIdentifier: String,
         remoteIdentityList: [PublicKey]) throws {
        try self.init(
            iterations: iterations,
            scannableVersion: scannableVersion,
            localStableIdentifier: localStableIdentifier,
            localIdentity: getLogicalKey(for: localIdentityList),
            remoteStableIdentifier: remoteStableIdentifier,
            remoteIdentity: getLogicalKey(for: remoteIdentityList))
    }
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
private func getFingerprint(identity: Data, stableIdentifier: String, iterations: Int) throws -> Data {
    var hashBuffer = [0, Fingerprint.version] + identity + stableIdentifier.asByteArray
    for _ in 0..<iterations {
        hashBuffer = try SignalCrypto.sha512(for: hashBuffer + [UInt8](identity))
    }
    guard hashBuffer.count >= Fingerprint.length else {
        throw SignalError(.invalidLength, "Invalid SHA512 hash length \(hashBuffer.count)")
    }
    return Data(hashBuffer)
}
