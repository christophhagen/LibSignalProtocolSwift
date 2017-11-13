//
//  ScannableFingerprint.swift
//  libsignal-protocol-swift
//
//  Created by User on 11.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

protocol ScannableFingerprint {

    static var version: Fingerprint.Version { get }

    var localFingerprint: Data { get }

    var remoteFingerprint: Data { get }

    func matches(_ other: ScannableFingerprint) throws -> Bool

    var object: Textsecure_CombinedFingerprints { get }

}

extension ScannableFingerprint {

    // MARK: Protocol Buffers

    var fingerprintObject: Textsecure_CombinedFingerprints {
        return Textsecure_CombinedFingerprints.with {
            $0.version = type(of: self).version.rawValue
            $0.localFingerprint = Textsecure_LogicalFingerprint.with {
                $0.content = self.localFingerprint
            }
            $0.remoteFingerprint = Textsecure_LogicalFingerprint.with {
                $0.content = self.remoteFingerprint
            }
        }
    }

    func data() throws -> Data {
        return try object.serializedData()
    }

    func fingerprintsMatch(_ lhs: ScannableFingerprint, _ rhs: ScannableFingerprint) throws -> Bool {
        guard type(of: lhs).version == type(of: rhs).version else {
            throw SignalError.fPVersionMismatch
        }
        return lhs.localFingerprint == rhs.remoteFingerprint &&
            lhs.remoteFingerprint == rhs.localFingerprint
    }
}

func createScannableFingerprint(from data: Data) throws -> ScannableFingerprint {
    let object = try Textsecure_CombinedFingerprints(serializedData: data)
    guard object.hasLocalFingerprint, object.hasRemoteFingerprint, object.hasVersion,
        object.localFingerprint.hasContent, object.remoteFingerprint.hasContent else {
            throw SignalError.invalidProtoBuf
    }
    guard let version = Fingerprint.Version(rawValue: object.version) else {
        throw SignalError.invalidVersion
    }
    switch version {
    case .version0:
        return try ScannableFingerprintV0(from: object) as ScannableFingerprint
    case .version1:
        return try ScannableFingerprintV1(from: object) as ScannableFingerprint
    }
}

struct ScannableFingerprintV0: ScannableFingerprint {

    static let version: Fingerprint.Version = .version0

    var localFingerprint: Data

    var remoteFingerprint: Data

    var localStableIdentifier: String

    var remoteStableIdentifier: String

    /**
     ScannableFingerprint Version 0
     */
    init(localStableIdentifier: String, localFingerprint: Data,
         remoteStableIdentifier: String, remoteFingerprint: Data) {
        self.localStableIdentifier = localStableIdentifier
        self.localFingerprint = localFingerprint
        self.remoteStableIdentifier = remoteStableIdentifier
        self.remoteFingerprint = remoteFingerprint
    }

    func matches(_ other: ScannableFingerprint) throws -> Bool {
        guard try fingerprintsMatch(self, other) else {
            return false
        }
        guard let rhs = other as? ScannableFingerprintV0 else {
            return false
        }
        guard self.localStableIdentifier == rhs.remoteStableIdentifier,
            self.remoteStableIdentifier == rhs.localStableIdentifier else {
                throw SignalError.fPIdentityMismatch
        }

        return self.localStableIdentifier == rhs.remoteStableIdentifier &&
            self.remoteStableIdentifier == rhs.localStableIdentifier
    }

    // MARK: Protocol buffers

    init(from object: Textsecure_CombinedFingerprints) throws {
        guard object.localFingerprint.hasIdentifier, object.remoteFingerprint.hasIdentifier else {
            throw SignalError.invalidProtoBuf
        }

        let local = object.localFingerprint
        let remote = object.remoteFingerprint
        guard let localId = String(data: local.identifier, encoding: .utf8),
            let remoteId = String(data: remote.identifier, encoding: .utf8) else {
                throw SignalError.invalidProtoBuf
        }
        self.localStableIdentifier = localId
        self.remoteStableIdentifier = remoteId
        self.localFingerprint = local.content
        self.remoteFingerprint = remote.content
    }

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

extension ScannableFingerprintV0: Equatable {
    static func ==(lhs: ScannableFingerprintV0, rhs: ScannableFingerprintV0) -> Bool {
        guard lhs.localStableIdentifier == rhs.localStableIdentifier,
            lhs.remoteStableIdentifier == rhs.remoteStableIdentifier else {
                return false
        }
        return lhs.localFingerprint == rhs.localFingerprint &&
            lhs.remoteFingerprint == rhs.remoteFingerprint
    }
}

struct ScannableFingerprintV1: ScannableFingerprint {

    static let version: Fingerprint.Version = .version1

    private static let length = 32

    var localFingerprint: Data

    var remoteFingerprint: Data

    /**
     ScannableFingerprint Version 1
     */
    init(localFingerprint: Data, remoteFingerprint: Data) throws {
        let length = ScannableFingerprintV1.length
        guard localFingerprint.count >= length,
            remoteFingerprint.count >= length else {
                throw SignalError.invalidLength
        }
        self.localFingerprint = localFingerprint[0..<length]
        self.remoteFingerprint = remoteFingerprint[0..<length]
    }

    func matches(_ other: ScannableFingerprint) throws -> Bool {
        guard try fingerprintsMatch(self, other) else {
            return false
        }
        return other is ScannableFingerprintV1
    }

    func matches(_ other: ScannableFingerprintV1) throws -> Bool {
        return try fingerprintsMatch(self, other)
    }

    fileprivate init(from object: Textsecure_CombinedFingerprints) throws {
        self.localFingerprint = object.localFingerprint.content
        self.remoteFingerprint = object.remoteFingerprint.content
    }

    var object: Textsecure_CombinedFingerprints {
        return self.fingerprintObject
    }
}

extension ScannableFingerprintV1: Equatable {
    static func ==(lhs: ScannableFingerprintV1, rhs: ScannableFingerprintV1) -> Bool {
        return lhs.localFingerprint == rhs.localFingerprint &&
            lhs.remoteFingerprint == rhs.remoteFingerprint
    }
}
