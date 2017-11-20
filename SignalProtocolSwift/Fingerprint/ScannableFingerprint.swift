//
//  ScannableFingerprint.swift
//  libsignal-protocol-swift
//
//  Created by User on 11.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 This protocol defines the main building blocks of a scannable fingerprint.
 */
protocol ScannableFingerprint {

    /// The fingerprint version
    static var version: Fingerprint.Version { get }

    /// The fingerprint data of the local party
    var localFingerprint: Data { get }

    /// The fingerprint data of the remote party
    var remoteFingerprint: Data { get }

    /**
    Compare two fingerprints for equality
     - parameter other: The other fingerprint to compare to.
     - returns: `True`, if the fingerprints match.
    */
    func matches(_ other: ScannableFingerprint) throws -> Bool

    /// The Protobuf object of the fingerprint
    var object: Textsecure_CombinedFingerprints { get }

}

extension ScannableFingerprint {

    // MARK: Protocol Buffers

    /// Create a ProtoBuf object populated with the fingerprint data
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

    /**
    Serialize a fingerprint.
     - throws: `SignalError` of type `invalidProtoBuf`
     - returns: The serialized fingerprint
     */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf,
                              "Could not serialize fingerprint: \(error.localizedDescription)")
        }
    }

    /**
     Compare two fingerprints for equality.
     - parameter lhs: The first fingerprint
     - parameter rhs: The second fingerprint
     - throws: `SignalError` of type `fPVersionMismatch` if the versions differ
     - returns: `True` if the fingerprints match
    */
    func fingerprintsMatch(_ lhs: ScannableFingerprint, _ rhs: ScannableFingerprint) throws -> Bool {
        guard type(of: lhs).version == type(of: rhs).version else {
            throw SignalError(.fPVersionMismatch, "Different fingerprint versions \(type(of: lhs).version), \(type(of: rhs).version)")
        }
        return lhs.localFingerprint == rhs.remoteFingerprint &&
            lhs.remoteFingerprint == rhs.localFingerprint
    }
}

/**
 Create a scannable fingerprint from data.
 - Note: The result is either a `ScannableFingerprintV0` or a `ScannableFingerprintV1`
 - parameter data: The data from which the fingerprint is to be created
 - throws: `SignalError` of type `invalidProtoBuf` and `invalidVersion`
 - returns: The deserialized fingerprint
 */
func createScannableFingerprint(from data: Data) throws -> ScannableFingerprint {
    let object: Textsecure_CombinedFingerprints
    do {
        object = try Textsecure_CombinedFingerprints(serializedData: data)
    } catch {
        throw SignalError(.invalidProtoBuf, "Could not deserialize data: \(error.localizedDescription)")
    }
    guard object.hasLocalFingerprint, object.hasRemoteFingerprint, object.hasVersion,
        object.localFingerprint.hasContent, object.remoteFingerprint.hasContent else {
            throw SignalError(.invalidProtoBuf, "Missing data in ProtoBuf object")
    }
    guard let version = Fingerprint.Version(rawValue: object.version) else {
        throw SignalError(.invalidVersion, "Invalid fingerprint version \(object.version)")
    }

    switch version {
    case .version0:
        return try ScannableFingerprintV0(from: object) as ScannableFingerprint
    case .version1:
        return try ScannableFingerprintV1(from: object) as ScannableFingerprint
    }
}

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

    /**
     Create a fingerprint from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    fileprivate init(from object: Textsecure_CombinedFingerprints) throws {
        try self.init(localFingerprint: object.localFingerprint.content,
                      remoteFingerprint: object.remoteFingerprint.content)
    }

    /// The fingerprint converted to a ProtoBuf object
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
