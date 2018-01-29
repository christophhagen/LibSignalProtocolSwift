//
//  DisplayableFingerprint.swift
//  SignalProtocolSwift-iOS
//
//  Created by User on 18.11.17.
//

import Foundation

/**
 A Fingerprint to verify the keys specifically for displaying to the user
 */
public struct DisplayableFingerprint {

    /// Fingerprint String of the local device
    let local: String

    /// Fingerprint String of the remote device
    let remote: String

    /// Displaytext
    public let displayText: String

    /**
     Create a displayable fingerprint from local and remote fingerprint data.
     - parameter local: The local fingerprint string
     - parameter remote: The remote fingerprint string
     */
    init(local: String, remote: String) {
        self.local = local
        self.remote = remote

        if local <= remote {
            self.displayText = local + remote
        } else {
            self.displayText = remote + local
        }
    }

    /**
     Create a displayable fingerprint from local and remote fingerprint data.
     - parameter localFingerprint: The local fingerprint data
     - parameter remoteFingerprint: The remote fingerprint data
     - throws: The `SignalError` with `invalidLength` if the fingerprint data is invalid
     */
    public init(localFingerprint: Data, remoteFingerprint: Data) throws {
        guard localFingerprint.count >= Fingerprint.length else {
            throw SignalError(.invalidLength, "Invalid local fingerprint length \(localFingerprint.count)")
        }
        guard remoteFingerprint.count >= Fingerprint.length else {
            throw SignalError(.invalidLength, "Invalid remote fingerprint length \(remoteFingerprint.count)")
        }
        let localString = DisplayableFingerprint.createDisplayString(fingerprint: localFingerprint)
        let remoteString = DisplayableFingerprint.createDisplayString(fingerprint: remoteFingerprint)
        self.init(local: localString, remote: remoteString)
    }

    /**
     Create a display string from fingerprint data.
     - parameter fingerprint: The fingerprint data
     - returns: The display string
    */
    private static func createDisplayString(fingerprint: Data) -> String {
        let data = fingerprint.map { UInt64($0) }
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

extension DisplayableFingerprint: Equatable {

    /**
     Compare two displayable fingerprints for equality.

     - parameter lhs: The first fingerprint
     - parameter rhs: The second fingerprint
     - returns: `true`, if the fingerprints are equal
     */
    public static func ==(lhs: DisplayableFingerprint, rhs: DisplayableFingerprint) -> Bool {
        return lhs.displayText == rhs.displayText
    }
}
