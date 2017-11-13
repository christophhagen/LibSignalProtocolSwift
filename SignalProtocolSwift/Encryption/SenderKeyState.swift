//
//  SenderKeyState.swift
//  libsignal-protocol-swift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

final class SenderKeyState {

    static let messageKeyMaximum = 2000

    var keyId: UInt32

    var chainKey: SenderChainKey

    var signaturePublicKey: PublicKey

    var signaturePrivateKey: PrivateKey?

    /// Dictionary of message keys indexed by iteration
    private var messageKeys: [SenderMessageKey]

    init(keyId: UInt32,
         chainKey: SenderChainKey,
         signaturePublicKey: PublicKey,
         signaturePrivateKey: PrivateKey?) {
        self.keyId = keyId
        self.chainKey = chainKey
        self.signaturePublicKey = signaturePublicKey
        self.signaturePrivateKey = signaturePrivateKey
        self.messageKeys = [SenderMessageKey]()
    }

    /**
     Add a `SenderMessageKey` to the keys which are stored to decrypt old (out of order) messages.
     - parameter messageKey: The keys to add
     - parameter removingOldKeys: Set to true, if old keys should be deleted if the maximum key number is reached.
    */
    func add(messageKey: SenderMessageKey, removingOldKeys: Bool = true) {
        messageKeys.insert(messageKey, at: 0)
        if removingOldKeys && messageKeys.count > SenderKeyState.messageKeyMaximum {
            messageKeys.removeLast(messageKeys.count - SenderKeyState.messageKeyMaximum)
        }
    }

    /**
     Get the message key for the iteration, if it exists.
     - parameter iteration: The iteration of the key
     - returns: The key for the iteration, or nil
    */
    func messageKey(for iteration: UInt32) -> SenderMessageKey? {
        for index in 0..<messageKeys.count {
            if messageKeys[index].iteration == iteration {
                return messageKeys.remove(at: index)
            }
        }
        return nil
    }

    /**
     Remove old message keys if the number is higher then the maximum.
    */
    func removeOldMessageKeys() {
        let count = messageKeys.count - SenderKeyState.messageKeyMaximum
        if count > 0 {
            messageKeys.removeLast(count)
        }
    }
    
    // MARK: Protocol Buffers

    convenience init(from data: Data) throws {
        let object = try Textsecure_SenderKeyStateStructure(serializedData: data)
        try self.init(from: object)
    }

    init(from object: Textsecure_SenderKeyStateStructure) throws {
        guard object.hasSenderKeyID, object.hasSenderChainKey,
            object.hasSenderSigningKey, object.senderSigningKey.hasPublic else {
            throw SignalError.invalidProtoBuf
        }
        self.keyId = object.senderKeyID
        self.chainKey = try SenderChainKey(from: object.senderChainKey)
        self.signaturePublicKey = try PublicKey(from: object.senderSigningKey.public)
        if object.senderSigningKey.hasPrivate {
            self.signaturePrivateKey = try PrivateKey(from: object.senderSigningKey.private)
        }
        self.messageKeys = try object.senderMessageKeys.map { try SenderMessageKey(from: $0) }
    }

    func object() throws -> Textsecure_SenderKeyStateStructure {
        return Textsecure_SenderKeyStateStructure.with {
            $0.senderKeyID = self.keyId
            $0.senderChainKey = self.chainKey.object
            $0.senderSigningKey = Textsecure_SenderKeyStateStructure.SenderSigningKey.with {
                $0.public = self.signaturePublicKey.data
                if let key = self.signaturePrivateKey {
                    $0.private = key.data
                }
            }
            $0.senderMessageKeys = self.messageKeys.map { $0.object }
        }
    }

    func data() throws -> Data {
        return try object().serializedData()
    }
}

extension SenderKeyState: Equatable {
    static func ==(lhs: SenderKeyState, rhs: SenderKeyState) -> Bool {
        return lhs.keyId == rhs.keyId &&
            lhs.chainKey == rhs.chainKey &&
            lhs.signaturePublicKey == rhs.signaturePublicKey &&
            lhs.signaturePrivateKey == rhs.signaturePrivateKey &&
            lhs.messageKeys == rhs.messageKeys
    }


}
