//
//  SignalError.swift
//  libsignal-protocol-swift
//
//  Created by User on 07.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

public enum SignalError: Error {
    case noMemory /* Not enough space */
    case invalid /* Invalid argument */
    /* Custom error codes for error conditions specific to the library */
    case unknown
    case curveError
    case storageError
    case duplicateMessage
    case invalidKey
    case invalidKeyID
    case invalidMac
    case invalidMessage
    case invalidVersion
    case invalidLength
    case legacyMessage
    case noSession
    case staleKeyExchange
    case untrustedIdentity
    case invalidSignature
    case invalidProtoBuf
    case fPVersionMismatch
    case fPIdentityMismatch

    case noCryptoDelegate
    case noRandomBytes
    case hmacError
    case digestError
    case encryptionError
    case decryptionError
}
