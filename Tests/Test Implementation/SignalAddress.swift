//
//  SignalAddress.swift
//  SignalProtocolSwift-iOS
//
//  Created by User on 18.11.17.
//

import Foundation

/**
 A `SignalAddress` identifies a single device of a Signal user, with a user
 `identifier` (such as a phone number), and the `deviceId` which specifies the device
 */
public struct SignalAddress {

    /// The unique identifier of a user (such as a phone number)
    public let identifier: String

    /// The identifier for the individual device of a user
    public let deviceId: UInt32

    /**
     Create a `SignalAddress`.
     - parameter identifier: The user identifier (such as phone number)
     - parameter deviceId: The id of the user's device
    */
    public init(identifier: String, deviceId: UInt32) {
        self.identifier = identifier
        self.deviceId = deviceId
    }
}

extension SignalAddress: Equatable {

    /**
     Compare two SignalAddresses. Two `SignalAddress` objects are
     equal if both their identifier and deviceId are equal.
     - parameter lhs: The first address
     - parameter rhs: The second address
     - returns: `True` if the addresses are equal.
    */
    public static func ==(lhs: SignalAddress, rhs: SignalAddress) -> Bool {
        return lhs.identifier == rhs.identifier && lhs.deviceId == rhs.deviceId
    }
}

extension SignalAddress: Hashable { }

extension SignalAddress: CustomStringConvertible {

    /**
     A description of the SignalAddress.
     */
    public var description: String {
        return "SignalAddress(\(identifier),\(deviceId))"
    }
}
