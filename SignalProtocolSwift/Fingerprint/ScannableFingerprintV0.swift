//
//  ScannableFingerprintV0.swift
//  SignalProtocolSwift iOS
//
//  Created by User on 28.01.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation

/**
 Version 0 of a scannable fingerprint.
 */
struct ScannableFingerprintV0: ScannableFingerprint {

    /// The fingerprint version (0)
    static let version: Fingerprint.Version = .version0

    /// The fingerprint data of the local party
    var localFingerprint: Data

    /// The fingerprint data of the remote party
    var remoteFingerprint: Data

    /// The identifier of the local party
    var localStableIdentifier: String

    /// The identifier of the remote party
    var remoteStableIdentifier: String

    /**
     Create a new ScannableFingerprint Version 0.
     - parameter localStableIdentifier: The identifier of the local party
     - parameter localFingerprint: The fingerprint data of the local party
     - parameter remoteStableIdentifier: The identifier of the remote party
     - parameter remoteFingerprint: The fingerprint data of the remote party
     */
    init(localStableIdentifier: String, localFingerprint: Data,
         remoteStableIdentifier: String, remoteFingerprint: Data) {
        self.localStableIdentifier = localStableIdentifier
        self.localFingerprint = localFingerprint
        self.remoteStableIdentifier = remoteStableIdentifier
        self.remoteFingerprint = remoteFingerprint
    }

    /**
     Compare two fingerprints for equality
     - note: Fingerprints match if the remote data of one fingerprint is equal to the local data of the other fingerprint, and vice versa.
     - parameter other: The other fingerprint to compare to.
     - returns: `True`, if the fingerprints match.
     - throws: `SignalError` of type `fPIdentityMismatch` and `fPVersionMismatch`
     */
    func matches(_ other: ScannableFingerprint) throws -> Bool {
        guard try fingerprintsMatch(self, other) else {
            return false
        }
        guard let rhs = other as? ScannableFingerprintV0 else {
            return false
        }
        guard self.localStableIdentifier == rhs.remoteStableIdentifier,
            self.remoteStableIdentifier == rhs.localStableIdentifier else {
                throw SignalError(.fPIdentityMismatch, "Identifiers don't match")
        }

        return self.localStableIdentifier == rhs.remoteStableIdentifier &&
            self.remoteStableIdentifier == rhs.localStableIdentifier
    }

    // MARK: Protocol buffers

    /**
     Create a fingerprint from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(from object: Textsecure_CombinedFingerprints) throws {
        guard object.localFingerprint.hasIdentifier, object.remoteFingerprint.hasIdentifier else {
            throw SignalError(.invalidProtoBuf, "Missing data in ProtoBuf object")
        }

        let local = object.localFingerprint
        let remote = object.remoteFingerprint
        guard let localId = String(data: local.identifier, encoding: .utf8),
            let remoteId = String(data: remote.identifier, encoding: .utf8) else {
                throw SignalError(.invalidProtoBuf, "Could not decode String data")
        }
        self.localStableIdentifier = localId
        self.remoteStableIdentifier = remoteId
        self.localFingerprint = local.content
        self.remoteFingerprint = remote.content
    }

    /// The fingerprint converted to a ProtoBuf object
    var object: Textsecure_CombinedFingerprints {
        var obj = self.fingerprintObject
        if let id = localStableIdentifier.data(using: .utf8) {
            obj.localFingerprint.identifier = id
        }
        if let id = remoteStableIdentifier.data(using: .utf8) {
            obj.remoteFingerprint.identifier = id
        }
        return obj
    }
}

// MARK: Protocol Equatable

extension ScannableFingerprintV0: Equatable {

    /**
     Compare two Fingerprints for equality.
     - parameter lhs: The first fingerprint
     - parameter rhs: The second fingerprint
     - returns: `true` if the fingerprints match
     */
    static func ==(lhs: ScannableFingerprintV0, rhs: ScannableFingerprintV0) -> Bool {
        guard lhs.localStableIdentifier == rhs.localStableIdentifier,
            lhs.remoteStableIdentifier == rhs.remoteStableIdentifier else {
                return false
        }
        return lhs.localFingerprint == rhs.localFingerprint &&
            lhs.remoteFingerprint == rhs.remoteFingerprint
    }
}
