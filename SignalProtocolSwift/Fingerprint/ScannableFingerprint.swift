//
//  ScannableFingerprint.swift
//  SignalProtocolSwift
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

// MARK: Protocol Buffers

extension ScannableFingerprint {

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

}

// MARK: Comparison

extension ScannableFingerprint {

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
