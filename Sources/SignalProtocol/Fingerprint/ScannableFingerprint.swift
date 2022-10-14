//
//  ScannableFingerprint.swift
//  SignalProtocolSwift
//
//  Created by User on 11.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 A fingerprint optimised to be scanned through e.g. a QR Code
 */
public struct ScannableFingerprint {

    /// The length of a fingerprint
    private static let length = 32

    /// The version of the fingerprint
    private static let version: UInt32 = 1

    /// The fingerprint data of the local party
    public let localFingerprint: Data

    /// The fingerprint data of the remote party
    public let remoteFingerprint: Data

    /**
     Create a new ScannableFingerprint Version 1.
     - parameter localFingerprint: The fingerprint data of the local party
     - parameter remoteFingerprint: The fingerprint data of the remote party
     - throws: `SignalError` of type `invalidLength`
     */
    init(localFingerprint: Data, remoteFingerprint: Data) throws {
        let length = ScannableFingerprint.length
        guard localFingerprint.count >= length,
            remoteFingerprint.count >= length else {
                throw SignalError(.invalidLength, "Invalid fingerprint lengths \(localFingerprint.count), \(remoteFingerprint.count)")
        }
        self.localFingerprint = localFingerprint[0..<length]
        self.remoteFingerprint = remoteFingerprint[0..<length]
    }
}

// MARK: Protocol Buffers

extension ScannableFingerprint: ProtocolBufferEquivalent {

    /**
     Create a fingerprint from a ProtoBuf object.
     - parameter object: The ProtoBuf object
     - throws: `SignalError` of type `invalidProtoBuf`
     */
    init(from object: Signal_Fingerprint) throws {
        guard object.hasLocal, object.hasRemote, object.hasVersion else {
            throw SignalError(.invalidProtoBuf, "Missing data in Fingerprint protobuf")
        }
        guard object.version == ScannableFingerprint.version else {
            throw SignalError(.invalidProtoBuf, "Invalid fingerprint version \(object.version)")
        }
        try self.init(localFingerprint: object.local,
                      remoteFingerprint: object.remote)
    }

    /// The fingerprint converted to a ProtoBuf object
    var protoObject: Signal_Fingerprint {
        return Signal_Fingerprint.with {
            $0.version = ScannableFingerprint.version
            $0.local = self.localFingerprint
            $0.remote = self.remoteFingerprint
        }
    }
}

// MARK: Comparison

extension ScannableFingerprint {

    /**
     Compare if fingerprints match, i.e. the local fingerprint matches the remote fingerprint and vice versa.
     - parameter lhs: The first fingerprint
     - parameter rhs: The second fingerprint
     - returns: `True` if the fingerprints match
    */
    public func matches(_ other: ScannableFingerprint) -> Bool {
        return localFingerprint == other.remoteFingerprint &&
            remoteFingerprint == other.localFingerprint
    }
}

// MARK: Protocol Equatable

extension ScannableFingerprint: Equatable {

    /**
     Compare two Fingerprints for equality.
     - parameter lhs: The first fingerprint
     - parameter rhs: The second fingerprint
     - returns: `true` if the fingerprints match
     */
    public static func ==(lhs: ScannableFingerprint, rhs: ScannableFingerprint) -> Bool {
        return lhs.localFingerprint == rhs.localFingerprint &&
            lhs.remoteFingerprint == rhs.remoteFingerprint
    }
}
