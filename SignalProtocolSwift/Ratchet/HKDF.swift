//
//  HKDF.swift
//  SignalProtocolSwift
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

    /// The total number of bytes to derive when creating a new root and chain key
    private static let derivedRootSecretsSize = RatchetRootKey.secretSize + RatchetChainKey.secretSize

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
     - note: The number of output bytes is not necessarily equal to the `outputLength` parameter.
     It is a multiple of the hash output size.
     - parameter material: The bytes used for the extract stage
     - parameter salt: The salt used for the extract stage
     - parameter info: The info used for the expand stage
     - parameter outputLength: The number of bytes to produce
     - returns: The derived bytes
     - throws: `SignalError` of type `hmacError`, if the HMAC authentication fails
     */
    func deriveSecrets(material: Data, salt: Data, info: Data, outputLength: Int) throws -> Data {
        // Extract step
        let prk = try SignalCrypto.hmacSHA256(for: material, with: salt)
        // Expand step
        return try expand(prk: prk, info: info, outputLength: outputLength)
    }

    /**
     Expand the bytes to create enough output bytes.
     - note: The number of output bytes is not necessarily equal to the `outputLength` parameter.
     It is a multiple of the hash output size.
     - parameter prk: The bytes to expand
     - parameter info: The info bytes to use within the expand step
     - parameter outputLength: The number of bytes to generate from the input
     - returns: The expanded bytes
     - throws: `SignalError` of type `hmacError` if the Crypto delegate fails to calculate the HMAC
    */
    private func expand(prk: Data, info: Data, outputLength: Int) throws -> Data {
        var fraction = Double(outputLength) / Double(RatchetChainKey.hashOutputSize)
        fraction.round(.up)
        let iterations = UInt8(fraction)

        var result = Data()
        var remainingLength = outputLength
        var stepBuffer = Data()

        for index in iterationStartOffset..<iterations+iterationStartOffset {
            let message = stepBuffer + info + [index]
            stepBuffer = try SignalCrypto.hmacSHA256(for: message, with: prk)
            let stepSize = min(remainingLength, stepBuffer.count)
            result += stepBuffer[0..<stepSize]
            remainingLength -= stepSize
        }
        return result
    }

    /**
     Create a new chain key and root key.
     - parameter material: The material to use to derive the secrets
     - parameter salt: The salt used to derive the secrets
     - parameter info: The info used to derive the secrets
     - throws: `SignalError.hmacError`, if the HMAC authentication fails
     - returns: A tuple of the root key and chain key
     */
    func chainAndRootKey(material: Data, salt: Data, info: Data) throws -> (rootKey: RatchetRootKey, chainKey: RatchetChainKey) {

        let derivedSecret = try deriveSecrets(
            material: material,
            salt: salt,
            info: info,
            outputLength: HKDF.derivedRootSecretsSize)

        let rootKeySecret = derivedSecret[0..<RatchetRootKey.secretSize]
        let newRootKey = RatchetRootKey(kdf: self, key: rootKeySecret)

        let chainKeySecret = derivedSecret[RatchetRootKey.secretSize..<HKDF.derivedRootSecretsSize]
        let newChainKey = RatchetChainKey(kdf: self, key: chainKeySecret, index: 0)

        return (newRootKey, newChainKey)
    }
}

extension HKDF: Comparable {
    /**
     Compare two HKDFs.
     - parameter lhs: The first KDF.
     - parameter rhs: The second KDF.
     - returns: `True` if the first argument is smaller than the second.
    */
    static func <(lhs: HKDF, rhs: HKDF) -> Bool {
        return lhs.iterationStartOffset < rhs.iterationStartOffset
    }

    /**
     Compare two HKDFs for equality.
     - parameter lhs: The first KDF.
     - parameter rhs: The second KDF.
     - returns: `True` if the KDFs are equal, i.e. their iteration offset matches.
     */
    static func ==(lhs: HKDF, rhs: HKDF) -> Bool {
        return lhs.iterationStartOffset == rhs.iterationStartOffset
    }
}

