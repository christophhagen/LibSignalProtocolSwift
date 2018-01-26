//
//  SessionState.swift
//  SignalProtocolSwift
//
//  Created by User on 08.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/// An elliptic key pair specifically used for identification in a ratchet
public typealias RatchetIdentityKeyPair = KeyPair

/// All parameters needed to establish a session
struct SymmetricParameters {

    /// The identity of the local party
    var ourIdentityKey: RatchetIdentityKeyPair

    /// The base key for the ratchet of the local party
    var ourBaseKey: KeyPair

    /// The initial key used for the ratchet
    var ourRatchetKey: KeyPair

    /// The base key of the remote party
    var theirBaseKey: PublicKey

    /// The ratchet key used by the remote party
    var theirRatchetKey: PublicKey

    /// The identity of the remote party
    var theirIdentityKey: PublicKey

    /// Indicate if the session was initialized as Alice
    var isAlice: Bool {
        // FIXME: This might be incorrect
        return ourBaseKey.publicKey < theirBaseKey
    }
}

/**
 A session state contains all data needed for communicating with a remote party.
 */
final class SessionState {

    /// The current version of the message encryption
    private static let cipherTextCurrentVersion: UInt8 = 3

    /// The maximum number of receiver chains for the remote party
    private static let maxReceiverChains = 5

    /// The info material used for the derivation of chain and root keys
    private static let keyInfo = "WhisperText".data(using: .utf8)!

    /// The version of the session
    var version: UInt8 = 2

    /// The last counter in the previous sender chain
    var previousCounter: UInt32 = 0

    /// the id of the remote party
    var remoteRegistrationID: UInt32 = 0

    /// The id of the local party
    var localRegistrationID: UInt32 = 0

    ///
    var needsRefresh: Bool = false

    /// The identity key of the local party
    var localIdentity: PublicKey?

    /// The identity key of the remote party
    var remoteIdentity: PublicKey?
    var rootKey: RatchetRootKey?
    var senderChain: SenderChain?
    var receiverChains: [ReceiverChain]
    var pendingPreKey: PendingPreKey?
    var aliceBaseKey: PublicKey?

    init() {
        self.receiverChains = [ReceiverChain]()
    }

    func receiverChain(for senderEphemeralKey: PublicKey) -> ReceiverChain? {
        for chain in receiverChains {
            if chain.ratchetKey == senderEphemeralKey {
                return chain
            }
        }
        return nil
    }

    func add(receiverChain: ReceiverChain) {
        receiverChains.insert(receiverChain, at: 0)
        if receiverChains.count > SessionState.maxReceiverChains {
            receiverChains.removeLast(receiverChains.count - SessionState.maxReceiverChains)
        }
    }

    func set(chainKey: RatchetChainKey, for senderEphemeralKey: PublicKey) throws {
        for index in 0..<receiverChains.count {
            if receiverChains[index].ratchetKey == senderEphemeralKey {
                receiverChains[index].chainKey = chainKey
                return
            }
        }
        throw SignalError(.unknown, "Couldn't find receiver chain to set chain key on")
    }

    func set(messageKeys: RatchetMessageKeys, for senderEphemeral: PublicKey) {
        if let chain = findReceiverChain(for: senderEphemeral) {
            chain.add(messageKey: messageKeys)
        }
    }

    func removeMessageKeys(for senderEphemeral: PublicKey, and counter: UInt32) -> RatchetMessageKeys? {

        guard let chain = findReceiverChain(for: senderEphemeral) else {
            return nil
        }
        return chain.removeMessageKey(for: counter)
    }

    func findReceiverChain(for senderEphemeral: PublicKey) -> ReceiverChain? {
        for item in receiverChains {
            if item.ratchetKey == senderEphemeral {
                return item
            }
        }
        return nil
    }

    func getReceiverChainKey(for senderEphemeral: PublicKey) -> RatchetChainKey? {
        return findReceiverChain(for: senderEphemeral)?.chainKey
    }

    func set(receiverChainKey: RatchetChainKey, for senderEphemeral: PublicKey) throws {
        guard let node = findReceiverChain(for: senderEphemeral) else {
            throw SignalError(.unknown, "Couldn't find receiver chain to set chain key on")
        }
        node.chainKey = receiverChainKey
    }

    func aliceInitialize(
        ourIdentityKey: RatchetIdentityKeyPair,
        ourBaseKey: KeyPair,
        theirIdentityKey: PublicKey,
        theirSignedPreKey: PublicKey,
        theirOneTimePreKey: PublicKey?,
        theirRatchetKey: PublicKey) throws {

        let sendingRatchetKey = try KeyPair()
        let secret1 = Data(repeating: 0xFF, count: 32)
        let secret2 = try theirSignedPreKey.calculateAgreement(privateKey: ourIdentityKey.privateKey)
        let secret3 = try theirIdentityKey.calculateAgreement(privateKey: ourBaseKey.privateKey)
        let secret4 = try theirSignedPreKey.calculateAgreement(privateKey: ourBaseKey.privateKey)
        let secret5 = try theirOneTimePreKey?.calculateAgreement(privateKey: ourBaseKey.privateKey) ?? Data()
        let secret = secret1 + secret2 + secret3 + secret4 + secret5

        let (derivedRoot, derivedChain) = try calculateDerivedKeys(secret: secret)

        let (sendingChainRoot, sendingChainKey) =
            try derivedRoot.createChain(
                theirRatchetKey: theirRatchetKey,
                ourRatchetKey: sendingRatchetKey.privateKey)

        add(receiverChain: ReceiverChain(
            ratchetKey: theirRatchetKey,
            chainKey: derivedChain))

        self.version = SessionState.cipherTextCurrentVersion
        self.remoteIdentity = theirIdentityKey
        self.localIdentity = ourIdentityKey.publicKey
        self.senderChain = SenderChain(
            ratchetKey: sendingRatchetKey,
            chainKey: sendingChainKey)
        self.rootKey = sendingChainRoot
    }

    func bobInitialize(
        ourIdentityKey: RatchetIdentityKeyPair,
        ourSignedPreKey: KeyPair,
        ourOneTimePreKey: KeyPair?,
        ourRatchetKey: KeyPair,
        theirIdentityKey: PublicKey,
        theirBaseKey: PublicKey) throws {

        let secret1 = Data(repeating: 0xFF, count: 32)
        let secret2 = try theirIdentityKey.calculateAgreement(privateKey: ourSignedPreKey.privateKey)
        let secret3 = try theirBaseKey.calculateAgreement(privateKey: ourIdentityKey.privateKey)
        let secret4 = try theirBaseKey.calculateAgreement(privateKey: ourSignedPreKey.privateKey)
        let secret5 = try ourOneTimePreKey?.privateKey.calculateAgreement(publicKey: theirBaseKey) ?? Data()
        let secret = secret1 + secret2 + secret3 + secret4 + secret5
        let (derivedRoot, derivedChain) = try calculateDerivedKeys(secret: secret)

        self.version = SessionState.cipherTextCurrentVersion
        self.remoteIdentity = theirIdentityKey
        self.localIdentity = ourIdentityKey.publicKey
        self.senderChain = SenderChain(ratchetKey: ourRatchetKey, chainKey: derivedChain)
        self.rootKey = derivedRoot
    }

    func symmetricInitialize(parameters params: SymmetricParameters) throws {

        if params.isAlice {
            try aliceInitialize(
                ourIdentityKey: params.ourIdentityKey,
                ourBaseKey: params.ourBaseKey,
                theirIdentityKey: params.theirIdentityKey,
                theirSignedPreKey: params.theirBaseKey,
                theirOneTimePreKey: nil,
                theirRatchetKey: params.theirRatchetKey)
        } else {
            try bobInitialize(
                ourIdentityKey: params.ourIdentityKey,
                ourSignedPreKey: params.ourBaseKey,
                ourOneTimePreKey: nil,
                ourRatchetKey: params.ourRatchetKey,
                theirIdentityKey: params.theirIdentityKey,
                theirBaseKey: params.theirBaseKey)
        }
    }

    private func calculateDerivedKeys(secret: Data) throws -> (rootKey: RatchetRootKey, chainKey: RatchetChainKey) {

        let kdf = HKDF(messageVersion: .version3)
        let salt = Data(count: RatchetChainKey.hashOutputSize)

        return try kdf.chainAndRootKey(material: secret, salt: salt, info: SessionState.keyInfo)
    }

    // MARK: Protocol Buffers
    
    init(from object: Textsecure_SessionStructure) throws {
        guard object.hasSessionVersion else {
            throw SignalError(.invalidProtoBuf, "Missing session version in SessionState ProtoBuf object")
        }
        if object.sessionVersion > UInt8.max {
            throw SignalError(.invalidProtoBuf, "Invalid session version \(object.sessionVersion)")
        }
        self.version = UInt8(object.sessionVersion)
        if object.hasLocalIdentityPublic {
            self.localIdentity = try PublicKey(from: object.localIdentityPublic)
        }
        if object.hasRemoteIdentityPublic {
            self.remoteIdentity = try PublicKey(from: object.remoteIdentityPublic)
        }
        guard let kdfVersion = HKDFVersion(rawValue: version) else {
            throw SignalError(.invalidVersion, "Invalid KDF version \(version)")
        }
        if object.hasRootKey {
            self.rootKey = RatchetRootKey(from: object.rootKey, version: kdfVersion)
        }
        self.previousCounter = object.previousCounter
        if object.hasSenderChain {
            self.senderChain = try SenderChain(from: object.senderChain, version: kdfVersion)
        }
        self.receiverChains = try object.receiverChains.map { try ReceiverChain(from: $0, version: kdfVersion) }
        if object.hasPendingPreKey {
            self.pendingPreKey = try PendingPreKey(serializedObject: object.pendingPreKey)
        }
        self.remoteRegistrationID = object.remoteRegistrationID
        self.localRegistrationID = object.localRegistrationID
        self.needsRefresh = object.needsRefresh
        if object.hasAliceBaseKey {
            self.aliceBaseKey = try PublicKey(from: object.aliceBaseKey)
        }
    }

    convenience init(from data: Data) throws {
        let object = try Textsecure_SessionStructure(serializedData: data)
        try self.init(from: object)
    }

    var object: Textsecure_SessionStructure {
        return Textsecure_SessionStructure.with {
            $0.sessionVersion = UInt32(self.version)
            if let item = self.localIdentity {
                $0.localIdentityPublic = item.data
            }
            if let item = self.remoteIdentity {
                $0.remoteIdentityPublic = item.data
            }
            if let item = self.rootKey {
                $0.rootKey = item.data
            }
            $0.previousCounter = self.previousCounter
            if let item = self.senderChain {
                $0.senderChain = item.object
            }
            $0.receiverChains = receiverChains.map { $0.object }
            if let item = self.pendingPreKey {
                $0.pendingPreKey = item.object
            }
            $0.remoteRegistrationID = self.remoteRegistrationID
            $0.localRegistrationID = self.localRegistrationID
            $0.needsRefresh = self.needsRefresh
            if let item = self.aliceBaseKey {
                $0.aliceBaseKey = item.data
            }
        }
    }
    
    func data() throws -> Data {
        return try object.serializedData()
    }
}

extension SessionState: Equatable {
    static func ==(lhs: SessionState, rhs: SessionState) -> Bool {
        guard lhs.version == rhs.version,
            lhs.previousCounter == rhs.previousCounter,
            lhs.remoteRegistrationID == rhs.remoteRegistrationID,
            lhs.localRegistrationID == rhs.localRegistrationID,
            lhs.needsRefresh == rhs.needsRefresh else {
                return false
        }
        guard lhs.localIdentity == rhs.localIdentity,
            lhs.remoteIdentity == rhs.remoteIdentity,
            lhs.rootKey == rhs.rootKey,
            lhs.senderChain == rhs.senderChain else {
                return false
        }
        guard lhs.receiverChains == rhs.receiverChains,
            lhs.pendingPreKey == rhs.pendingPreKey,
            lhs.aliceBaseKey == rhs.aliceBaseKey else {
                return false
        }
        return true
    }
}

