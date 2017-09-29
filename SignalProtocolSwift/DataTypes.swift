//
//  CHDataTypes.swift
//  TestC
//
//  Created by User on 20.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/// Encrypted byte message produced by the signal protocol
typealias EncryptedData = [UInt8]
/// Input for the encryption methods
typealias UnencryptedData = [UInt8]

/// A pre key needed for establishing a session
typealias PreKey = [UInt8]
/// A pre key bundle needed for establishing a session
typealias PreKeyBundle = [UInt8]
/// An initial message for establishing a session, created by using a pre key and bundle
typealias PreKeyMessage = [UInt8]
/// The number of a Pre Key
typealias PreKeyID = UInt32

/// A pair of public and private identity key, serialized
typealias IdentityKeyPair = [UInt8]

/// The id of a Signed Pre Key
typealias SignedPreKeyID = UInt32
/// The device number
typealias DeviceID = Int32

/**
 An address to establish a session with a peer.
 */
struct CHAddress: Hashable, CustomStringConvertible {

    // MARK: Variables

    /// maximum byte length of the recipient ID
    private static let maximumLength = 50

    /// The device identification number
    var deviceID: DeviceID

    /// The recipient id, i.e. phone number or e-mail
    var recipientID: String

    // MARK: Initialization

    /**
     Create a new address.

     - parameter deviceID: The identification number of the device
     - parameter recipientID: The phone number or similar identification token
     */
    init(deviceID: DeviceID, recipientID: String) {
        self.deviceID = deviceID
        self.recipientID = recipientID
    }

    /**
     Create a new address from a pointer to a signal API struct.
     - note: Fails if the pointer is nil, the recipient ID is too long (see `CHAddress.maximumLength`), or the recipient ID is not a valid String
     - parameter address: Pointer to the struct.
     */
    init?(from address: UnsafePointer<signal_protocol_address>?) {
        guard let unpacked = address?.pointee else {
            return nil
        }
        deviceID = unpacked.device_id
        guard unpacked.name_len < CHAddress.maximumLength else {
            return nil
        }
        guard let string = stringFromBuffer(unpacked.name, length: unpacked.name_len) else {
            return nil
        }
        recipientID = string
    }

    /**
     Create a new address from a signal API struct.
     - note: Fails if the recipient ID is too long (see `CHAddress.maximumLength`), or the recipient ID is not a valid String
     - parameter address: Pointer to the struct.
     */
    init?(address: signal_protocol_address) {
        guard address.name_len < CHAddress.maximumLength else {
            return nil
        }
        guard let string = stringFromBuffer(address.name, length: address.name_len) else {
            return nil
        }
        self.deviceID = address.device_id
        self.recipientID = string
    }

    // MARK: Protocol CustomStringConvertible

    /// A description of the address, contains the device ID and the recipient ID
    var description: String {
        return "Address(\(deviceID),\(recipientID))"
    }

    // MARK: Protocol Hashable

    /// A hash of the address for storage
    var hashValue: Int {
        return recipientID.hashValue
    }

    /// Two addresses are equal if the device ID and recipient ID match
    static func ==(lhs: CHAddress, rhs: CHAddress) -> Bool {
        if lhs.deviceID != rhs.deviceID {
            return false
        }
        return lhs.recipientID == rhs.recipientID
    }
}
