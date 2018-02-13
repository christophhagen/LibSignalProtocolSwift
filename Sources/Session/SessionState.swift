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
final class SessionState: ProtocolBufferEquivalent {

    /// The maximum number of receiver chains for the remote party
    private static let maxReceiverChains = 5

    /// The info material used for the derivation of chain and root keys
    private static let keyInfo = "WhisperText".data(using: .utf8)!

    /// The last counter in the previous sender chain
    var previousCounter: UInt32 = 0

    /// The identity key of the local party
    var localIdentity: PublicKey?

    /// The identity key of the remote party
    var remoteIdentity: PublicKey?

    /// The root key of the state
    var rootKey: RatchetRootKey?

    /// The sender chain of the state
    var senderChain: SenderChain?

    /// The receiver chains of the state
    var receiverChains: [ReceiverChain]

    /// An optional pending pre key
    var pendingPreKey: PendingPreKey?

    /// The base key
    var aliceBaseKey: PublicKey?

    /**
     Create a new sender state
     */
    init() {
        self.receiverChains = [ReceiverChain]()
    }

    /**
     Find a receiver chain for a sender key.
     - parameter senderEphemeralKey: The public key of the receiver chain
     - returns: The receiver chain for the key, or nil
     */
    func receiverChain(for senderEphemeralKey: PublicKey) -> ReceiverChain? {
        for chain in receiverChains {
            if chain.ratchetKey == senderEphemeralKey {
                return chain
            }
        }
        return nil
    }

    /**
     Add a receiver chain to the state.
     - parameter receiverChain: The chain to add
     */
    func add(receiverChain: ReceiverChain) {
        receiverChains.insert(receiverChain, at: 0)
        if receiverChains.count > SessionState.maxReceiverChains {
            receiverChains.removeLast(receiverChains.count - SessionState.maxReceiverChains)
        }
    }

    /**
     Set the chain key for a given sender key
     - parameter chainKey: The chain key to set
     - parameter senderEphemeralKey: The key of the receiver chain
     - throws: `SignalError` of type `.unknown`, if no receiver chain matches the key
     */
    func set(chainKey: RatchetChainKey, for senderEphemeralKey: PublicKey) throws {
        for index in 0..<receiverChains.count {
            if receiverChains[index].ratchetKey == senderEphemeralKey {
                receiverChains[index].chainKey = chainKey
                return
            }
        }
        throw SignalError(.unknown, "Couldn't find receiver chain to set chain key on")
    }

    /**
     Set the message keys for a given sender key
     - parameter messageKeys: The keys to set
     - parameter senderEphemeral: The key of the receiver chain
     - throws: `SignalError` of type `.unknown`, if no receiver chain matches the key
     */
    func set(messageKeys: RatchetMessageKeys, for senderEphemeral: PublicKey) {
        if let chain = receiverChain(for: senderEphemeral) {
            chain.add(messageKey: messageKeys)
        }
    }

    /**
     Remove message keys
     - parameter senderEphemeral: The key of the receiver chain
     - parameter counter: The message counter in the chain
     - returns: The removed message keys, if found
     */
    func removeMessageKeys(for senderEphemeral: PublicKey, and counter: UInt32) -> RatchetMessageKeys? {
        guard let chain = receiverChain(for: senderEphemeral) else {
            return nil
        }
        return chain.removeMessageKey(for: counter)
    }

    /**
     Find the chain key of a receiver chain
     - parameter senderEphemeral: The key of the receiver chain
     - returns: The chain key, if found
     */
    func receiverChainKey(for senderEphemeral: PublicKey) -> RatchetChainKey? {
        return receiverChain(for: senderEphemeral)?.chainKey
    }

    /**
     Set the chain key of a receiver chain
     - parameter senderEphemeral: The key of the receiver chain
     - parameter receiverChainKey: The chain key to set
     - throws: `SignalError` of type `.unknown`, if no receiver chain matches the key
     */
    func set(receiverChainKey: RatchetChainKey, for senderEphemeral: PublicKey) throws {
        guard let node = receiverChain(for: senderEphemeral) else {
            throw SignalError(.unknown, "Couldn't find receiver chain to set chain key on")
        }
        node.chainKey = receiverChainKey
    }

    /**
     Initialise a session state.
     - parameter ourIdentityKey: The local identity key
     - parameter ourBaseKey: The local base key
     - parameter theirIdentityKey: The remote identity key
     - parameter theirSignedPreKey: The signed pre key of the remote
     - parameter theirOneTimePreKey: The public pre key of the remote
     - parameter theirRatchetKey: The public key of the remote ratchet
     - throws: `SignalError` errors
     */
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

        self.remoteIdentity = theirIdentityKey
        self.localIdentity = ourIdentityKey.publicKey
        self.senderChain = SenderChain(
            ratchetKey: sendingRatchetKey,
            chainKey: sendingChainKey)
        self.rootKey = sendingChainRoot
    }

    /**
     Initialise a session state.
     - parameter ourIdentityKey: The local identity key
     - parameter ourSignedPreKey: The local signed pre key
     - parameter ourOneTimePreKey: The local pre key
     - parameter ourRatchetKey: The local ratchet key
     - parameter theirIdentityKey: The identity key of the remote
     - parameter theirBaseKey: The base key of the remote
     - throws: `SignalError` errors
     */
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

        self.remoteIdentity = theirIdentityKey
        self.localIdentity = ourIdentityKey.publicKey
        self.senderChain = SenderChain(ratchetKey: ourRatchetKey, chainKey: derivedChain)
        self.rootKey = derivedRoot
    }

    /**
     Initialise a session state.
     - parameter params: The keys for initialization
     - throws: `SignalError` errors
     */
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

    /**
     Create the root and chain key from the secret.
     - parameter secret: The input for the KDF
     - returns: The root and chain key
     */
    private func calculateDerivedKeys(secret: Data) throws -> (rootKey: RatchetRootKey, chainKey: RatchetChainKey) {
        let salt = Data(count: RatchetChainKey.hashOutputSize)
        return try HKDF.chainAndRootKey(material: secret, salt: salt, info: SessionState.keyInfo)
    }

    // MARK: Protocol Buffers

    /// The state converted to a protobuf object
    var protoObject: Signal_Session {
        return Signal_Session.with {
            if let item = self.localIdentity {
                $0.localIdentityPublic = item.data
            }
            if let item = self.remoteIdentity {
                $0.remoteIdentityPublic = item.data
            }
            if let item = self.rootKey {
                $0.rootKey = item.protoData()
            }
            $0.previousCounter = self.previousCounter
            if let item = self.senderChain {
                $0.senderChain = item.protoObject
            }
            $0.receiverChains = receiverChains.map { $0.protoObject }
            if let item = self.pendingPreKey {
                $0.pendingPreKey = item.protoObject
            }
            if let item = self.aliceBaseKey {
                $0.aliceBaseKey = item.data
            }
        }
    }

    /**
     Create a state from a protobuf object.
     - parameter protoObject: The protobuf object.
     - throws: `SignalError` of type `.invalidProtoBuf`
     */
    init(from protoObject: Signal_Session) throws {
        if protoObject.hasLocalIdentityPublic {
            self.localIdentity = try PublicKey(from: protoObject.localIdentityPublic)
        }
        if protoObject.hasRemoteIdentityPublic {
            self.remoteIdentity = try PublicKey(from: protoObject.remoteIdentityPublic)
        }
        if protoObject.hasRootKey {
            self.rootKey = RatchetRootKey(from: protoObject.rootKey)
        }
        self.previousCounter = protoObject.previousCounter
        if protoObject.hasSenderChain {
            self.senderChain = try SenderChain(from: protoObject.senderChain)
        }
        self.receiverChains = try protoObject.receiverChains.map { try ReceiverChain(from: $0) }
        if protoObject.hasPendingPreKey {
            self.pendingPreKey = try PendingPreKey(from: protoObject.pendingPreKey)
        }
        if protoObject.hasAliceBaseKey {
            self.aliceBaseKey = try PublicKey(from: protoObject.aliceBaseKey)
        }
    }
}

// MARK: Protocol Equatable

extension SessionState: Equatable {

    /**
     Compare tow session states.
     - parameter lhs: The first state
     - parameter rhs: The second state
     - returns: `true` if the states are equal
     */
    static func ==(lhs: SessionState, rhs: SessionState) -> Bool {
        guard lhs.previousCounter == rhs.previousCounter else {
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

