//
//  PreKeyBundle.swift
//  SignalCommunication-iOS
//
//  Created by User on 16.11.17.
//

import Foundation

/**
 A PreKeyBundle is used to establish a new session.
 */
public struct PreKeyBundle {

    /// The identity of the remote client to which a session should be established.
    let identity: Identity

    /// The signed pre key used for authentication
    let signedPreKey: SignedPreKey

    /// A one time pre key used for uniqueness
    let preKey: PreKey?

    /// The identity of the remote client to which a session should be established.
    public struct Identity {

        /// The public key of the identity key pair of the remote client
        let key: PublicKey

        /// The registration id of the remote client
        let registrationId: UInt32

        /// Create an identity from the components
        public init(key: PublicKey, registrationId: UInt32) {
            self.key = key
            self.registrationId = registrationId
        }
    }

    /// The signed pre key used for authentication
    public struct SignedPreKey {

        /// The identification number to distinguish the keys
        let id: UInt32

        /// The public key of the signed pre key pair
        let key: PublicKey

        /// The signature of the key
        let signature: Data

        /// Create a signed pre key from the components
        public init(id: UInt32, key: PublicKey, signature: Data) {
            self.id = id
            self.key = key
            self.signature = signature
        }
    }

    /// A one time pre key used for uniqueness
    public struct PreKey {

        /// The identification number to distinguish the keys
        let id: UInt32

        /// The public key of the pre key pair
        let key: PublicKey

        /// Create a pre key from the components
        public init(id: UInt32, key: PublicKey) {
            self.id = id
            self.key = key
        }
    }
}
