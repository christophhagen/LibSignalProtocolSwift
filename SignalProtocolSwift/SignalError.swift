//
//  SignalError.swift
//  TestC
//
//  Created by User on 29.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


/// Log level definitions
enum SignalLogLevel: Int32 {
    /// Severe problem that can't be coped with
    case error = 0
    /// Unusual problem that might affect overall usability
    case warning = 1
    /// Something that might be worth fixing
    case notice = 2
    /// Information about important activities
    case info = 3
    /// Low level information useful only for debugging
    case debug = 4
}

/**
 Error definitions for errors thrown or handled by the `SignalInterface` class.
 */
enum SignalErrorType: String {
    /// The recipient ID can not be represented as a UTF-8 String
    case invalidRecipientID = "Invalid Recipient ID"
    /// No session exists for the given address
    case noSession = "No session for address"
    /// Could not encrypt the message
    case encryptFailed = "Encrypt failed"
    /// Could not decrypt the message
    case decryptFailed = "Decrypt failed"
    /// Either the Pre Key Bundle or the Pre Key are invalid
    case invalidPreKeyBundle = "Invalid Pre Key Bundle or Pre Key"
    /// Message is not a valid String
    case notTextMessage = "Message is not a String"
    /// Message Type is incorrect
    case wrongMessageType = "Wrong message type"
    /// Saving or loading from the store failed
    case keyStoreFailure = "Problem with key storage"
    /// Key material is corrupt
    case corruptKey = "Key corrupt"
    /// Couldn't create new Key Pair
    case noKeyCreated = "No key pair created"
    /// Setup broken, either no context, no log, no crypto, or no locking
    case invalidRessource = "Ressource missing or unset"
    /// A new session with an already existing identity key
    case untrustedIdentity = "Untrusted identity"
}

/**
 Error struct for errors thrown or handled by the `SignalInterface` class.
 All external errors are of this type.
 */
struct SignalError: Error, CustomStringConvertible {

    /// The type of the error, see `SignalErrorType`
    let type: SignalErrorType
    /// A String with a description of the error
    let message: String?
    /// An optional error code from the Signal API
    let code: Int32?

    /**
     Create a new error.
     - parameter type: The error type
     - parameter message: A description of the error
     - parameter code: Optional internal error from the Signal API
     */
    init(type: SignalErrorType, message: String? = nil, code: Int32? = nil) {
        self.type = type
        self.message = message
        self.code = code
    }

    /// Printable description of the error
    var description: String {
        var text = "Error: " + type.rawValue
        if message != nil {
            text += ": " + message!
        }
        if code != nil {
            text += " (\(code!))"
        }
        return text
    }

}
