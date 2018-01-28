//
//  ScannableFingerprintV1.swift
//  SignalProtocolSwift iOS
//
//  Created by User on 28.01.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation

/**
 A fingerprint optimised to be scanned through e.g. a QR Code
 */
struct ScannableFingerprintV1: ScannableFingerprint {

    /// The fingerprint version (1)
    static let version: Fingerprint.Version = .version1

    /// The length of a fingerprint
    private static let length = 32

    /// The fingerprint data of the local party
    var localFingerprint: Data

    /// The fingerprint data of the remote party
    var remoteFingerprint: Data

    /**
     Create a new ScannableFingerprint Version 1.
     - parameter localFingerprint: The fingerprint data of the local party
     - parameter remoteFingerprint: The fingerprint data of the remote party
     - throws: `SignalError` of type `invalidLength`
     */
    init(localFingerprint: Data, remoteFingerprint: Data) throws {
        let length = ScannableFingerprintV1.length
        guard localFingerprint.count >= length,
            remoteFingerprint.count >= length else {
                throw SignalError(.invalidLength, "Invalid fingerprint lengths \(localFingerprint.count), \(remoteFingerprint.count)")
        }
        self.localFingerprint = localFingerprint[0..<length]
        self.remoteFingerprint = remoteFingerprint[0..<length]
    }
}

// MARK: Comparison

extension ScannableFingerprintV1 {

    /**
     Compare two fingerprints for equality
     - note: Fingerprints match if the remote data of one fingerprint is equal to the local data of the other fingerprint, and vice versa.
     - parameter other: The other fingerprint to compare to.
     - returns: `True`, if the fingerprints match.
     - throws: `SignalError` of type `fPVersionMismatch`
     */
    func matches(_ other: ScannableFingerprint) throws -> Bool {
        guard try fingerprintsMatch(self, other) else {
            return false
        }
        return other is ScannableFingerprintV1
    }

    /**
     Compare two fingerprints for equality
     - note: Fingerprints match if the remote data of one fingerprint is equal to the local data of the other fingerprint, and vice versa.
     - parameter other: The other fingerprint to compare to.
     - returns: `True`, if the fingerprints match.
     - throws: `SignalError` of type `fPVersionMismatch`
     */
    func matches(_ other: ScannableFingerprintV1) throws -> Bool {
        return try fingerprintsMatch(self, other)
    }

}

// MARK: Protocol buffers

extension ScannableFingerprintV1 {

    /**
     Create a fingerprint from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(from object: Textsecure_CombinedFingerprints) throws {
        try self.init(localFingerprint: object.localFingerprint.content,
                      remoteFingerprint: object.remoteFingerprint.content)
    }

    /// The fingerprint converted to a ProtoBuf object
    var object: Textsecure_CombinedFingerprints {
        return self.fingerprintObject
    }
}

// MARK: Protocol Equatable

extension ScannableFingerprintV1: Equatable {

    /**
     Compare two Fingerprints for equality.
     - parameter lhs: The first fingerprint
     - parameter rhs: The second fingerprint
     - returns: `true` if the fingerprints match
     */
    static func ==(lhs: ScannableFingerprintV1, rhs: ScannableFingerprintV1) -> Bool {
        return lhs.localFingerprint == rhs.localFingerprint &&
            lhs.remoteFingerprint == rhs.remoteFingerprint
    }
}
