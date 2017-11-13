//
//  SessionState.swift
//  libsignal-protocol-swift
//
//  Created by User on 08.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


typealias RatchetIdentityKeyPair = KeyPair

struct SymmetricParameters {
    var ourIdentityKey: RatchetIdentityKeyPair
    var ourBaseKey: KeyPair
    var ourRatchetKey: KeyPair
    var theirBaseKey: PublicKey
    var theirRatchetKey: PublicKey
    var theirIdentityKey: PublicKey

    var isAlice: Bool {
        // FIXME: This might be incorrect
        return ourBaseKey.publicKey < theirBaseKey
    }
}


final class SessionState {
    
    private static let cipherTextCurrentVersion: UInt8 = 3
    private static let maxReceiverChains = 5

    var version: UInt8 = 2
    var previousCounter: UInt32 = 0
    var remoteRegistrationID: UInt32 = 0
    var localRegistrationID: UInt32 = 0
    var needsRefresh: Bool = false

    var localIdentity: PublicKey?
    var remoteIdentity: PublicKey?
    var rootKey: RatchetRootKey?
    var senderChain: SenderChain?
    var receiverChains: [ReceiverChain]
    var pendingKeyExchange: PendingKeyExchange?
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

    func set(chainKey: RatchetChainKey, for senderEphemeralKey: PublicKey) {
        for index in 0..<receiverChains.count {
            if receiverChains[index].ratchetKey == senderEphemeralKey {
                receiverChains[index].chainKey = chainKey
                return
            }
        }
        signalLog(level: .warning, "Couldn't find receiver chain to set chain key on")
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
            signalLog(level: .warning, "Couldn't find receiver chain to set chain key on")
            throw SignalError.unknown
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
        let secret1 = [UInt8](repeating: 0xFF, count: 32)
        let secret2 = try theirSignedPreKey.calculateAgreement(privateKey: ourIdentityKey.privateKey)
        let secret3 = try theirIdentityKey.calculateAgreement(privateKey: ourBaseKey.privateKey)
        let secret4 = try theirSignedPreKey.calculateAgreement(privateKey: ourBaseKey.privateKey)
        let secret5 = try theirOneTimePreKey?.calculateAgreement(privateKey: ourBaseKey.privateKey) ?? []
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

        let secret1 = [UInt8](repeating: 0xFF, count: 32)
        let secret2 = try theirIdentityKey.calculateAgreement(privateKey: ourSignedPreKey.privateKey)
        let secret3 = try theirBaseKey.calculateAgreement(privateKey: ourIdentityKey.privateKey)
        let secret4 = try theirBaseKey.calculateAgreement(privateKey: ourSignedPreKey.privateKey)
        let secret5 = try ourOneTimePreKey?.privateKey.calculateAgreement(publicKey: theirBaseKey) ?? []
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

    private func calculateDerivedKeys(secret: [UInt8]) throws -> (rootKey: RatchetRootKey, chainKey: RatchetChainKey) {

        let keyInfo = [UInt8]("WhisperText".utf8)

        let kdf = HKDF(messageVersion: .version3)
        let salt = [UInt8](repeating: 0, count: RatchetChainKey.hashOutputSize)

        let output = try kdf.deriveSecrets(material: secret, salt: salt, info: keyInfo, outputLength: RatchetRootKey.derivedRootSecretsSize)

        let rootKeyMaterial = Array(output[0..<RatchetRootKey.secretSize])
        let rootKey = RatchetRootKey(kdf: kdf, key: rootKeyMaterial)

        let chainKeyMaterial = Array(output[RatchetRootKey.secretSize..<output.count])
        let chainKey = RatchetChainKey(kdf: kdf, key: chainKeyMaterial, index: 0)

        return (rootKey, chainKey)
    }

    // MARK: Protocol Buffers
    
    init(from object: Textsecure_SessionStructure) throws {
        if object.sessionVersion > UInt8.max { throw SignalError.invalidProtoBuf }
        self.version = UInt8(object.sessionVersion)
        if object.hasLocalIdentityPublic {
            self.localIdentity = try PublicKey(from: object.localIdentityPublic)
        }
        if object.hasRemoteIdentityPublic {
            self.remoteIdentity = try PublicKey(from: object.remoteIdentityPublic)
        }
        guard let kdfVersion = HKDFVersion(rawValue: version) else {
            throw SignalError.invalidVersion
        }
        if object.hasRootKey {
            self.rootKey = RatchetRootKey(from: object.rootKey, version: kdfVersion)
        }
        self.previousCounter = object.previousCounter
        if object.hasSenderChain {
            self.senderChain = try SenderChain(from: object.senderChain, version: kdfVersion)
        }
        self.receiverChains = try object.receiverChains.map { try ReceiverChain(from: $0, version: kdfVersion) }
        if object.hasPendingKeyExchange {
            self.pendingKeyExchange = try PendingKeyExchange(serializedObject: object.pendingKeyExchange)
        }
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

    func object() throws -> Textsecure_SessionStructure {
        return try Textsecure_SessionStructure.with {
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
            if let item = self.pendingKeyExchange {
                $0.pendingKeyExchange = try item.serializedObject()
            }
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
        return try object().serializedData()
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
        lhs.pendingKeyExchange == rhs.pendingKeyExchange,
        lhs.pendingPreKey == rhs.pendingPreKey,
            lhs.aliceBaseKey == rhs.aliceBaseKey else {
                return false
        }
        return true
    }
}

