//
//  HKDF.swift
//  libsignal-protocol-swift
//
//  Created by User on 08.10.17.
//  Copyright © 2017 User. All rights reserved.
//

/**
 The different versions of the HKDF
 */
enum HKDFVersion: UInt8 {
    /// Older messages have an iteration offset of 0
    case version2 = 2
    /// Newer messages have an iteration offset of 1
    case version3 = 3
}

/**
 The Key derivation function used for the Ratchet.
 */
struct HKDF {

    /// The offset for the expand iterations, depending on the version
    private let iterationStartOffset: UInt8

    /**
     Initialize a new KDF with the message version
     - parameter messageVersion: The version of the messages
    */
    init(messageVersion: HKDFVersion) {
        switch messageVersion {
        case .version2:
            self.iterationStartOffset = 0
        case .version3:
            self.iterationStartOffset = 1
        }
    }

    /**
     Derive new secrets from the KDF.
     - parameter material: The bytes used for the extract stage
     - parameter salt: The salt used for the extract stage
     - parameter info: The info used for the expand stage
     - parameter outputLength: The number of bytes to produce
     - returns: The derived bytes
     - throws: `SignalError.hmacError`, if the HMAC authentication fails
     */
    func deriveSecrets(material: [UInt8], salt: [UInt8], info: [UInt8], outputLength: Int) throws -> [UInt8] {
        let prk = try extract(salt: salt, material: material)
        return try expand(prk: prk, info: info, outputLength: outputLength)
    }

    private func extract(salt: [UInt8], material: [UInt8]) throws -> [UInt8] {
        return try SignalCrypto.hmacSHA256(for: material, with: salt)
    }

    private func expand(prk: [UInt8], info: [UInt8], outputLength: Int) throws -> [UInt8] {
        var fraction = Double(outputLength) / Double(RatchetChainKey.hashOutputSize)
        fraction.round(.up)
        let iterations = UInt8(fraction)

        var result = [UInt8]()
        var remainingLength = outputLength
        var stepBuffer = [UInt8]()

        for index in iterationStartOffset..<iterations+iterationStartOffset {
            let message = stepBuffer + info + [index]
            do {
                stepBuffer = try SignalCrypto.hmacSHA256(for: message, with: prk)
            } catch {
                throw SignalError.hmacError
            }
            let stepSize = min(remainingLength, stepBuffer.count)
            result += stepBuffer[0..<stepSize]
            remainingLength -= stepSize
        }
        return result
    }
}

extension HKDF: Comparable {
    static func <(lhs: HKDF, rhs: HKDF) -> Bool {
        return lhs.iterationStartOffset < rhs.iterationStartOffset
    }

    static func ==(lhs: HKDF, rhs: HKDF) -> Bool {
        return lhs.iterationStartOffset == rhs.iterationStartOffset
    }
}

