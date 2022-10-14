//
//  DeviceConsistencyMessage.swift
//  SignalProtocolSwift-iOS
//
//  Created by User on 18.11.17.
//

import Foundation

/**
 Device consistency messages can be sent between multiple devices to verify that the
 identity keys and are consistent across devices.
 */
struct DeviceConsistencyMessage {

    /// The consistency signature
    var signature: DeviceConsistencySignature

    /// The generation of the consistency message
    var generation: UInt32

    /**
     Create a new consistency message.
     - parameter commitment: The hashed identity keys
     - parameter identityKeyPair: The key pair of the sender
     - throws: `SignalError` errors
    */
    init(commitment: DeviceConsistencyCommitmentV0, identitykeyPair: KeyPair) throws {

        let serialized = commitment.serialized

        /* Calculate VRF signature */
        let signature = try identitykeyPair.privateKey.signVRF(message: serialized)

        /* Verify VRF signature */
        let vrfOutput = try identitykeyPair.publicKey.verify(vrfSignature: signature, for: serialized)

        /* Create and assign the signature */
        self.signature = DeviceConsistencySignature(signature: signature, vrfOutput: vrfOutput)
        self.generation = commitment.generation
    }
}

// MARK: Protocol Buffers

extension DeviceConsistencyMessage {

    /**
     The message converted to a protocol buffer object.
     */
    var object: Signal_DeviceConsistencyCodeMessage {
        return Signal_DeviceConsistencyCodeMessage.with {
            $0.generation = self.generation
            $0.signature = self.signature.signature
        }
    }

    /**
     Create a consistency message from a protocol buffer object.
     - parameter object: The protocol buffer object
     - parameter commitment: The commitment needed for verification
     - parameter identityKey: The identity key needed for verification
     - throws: `SignalError` errors
     */
    init(from object: Signal_DeviceConsistencyCodeMessage,
         commitment: DeviceConsistencyCommitmentV0,
         identityKey: PublicKey) throws {
        guard object.hasSignature, object.hasGeneration else {
            throw SignalError(.invalidProtoBuf, "Missing data in ProtoBuf object")
        }

        /* Verify VRF signature */
        let vrfOutput = try identityKey.verify(vrfSignature: object.signature, for: commitment.serialized)

        /* Assign the message fields */
        self.generation = object.generation
        self.signature = DeviceConsistencySignature(signature: object.signature, vrfOutput: vrfOutput)
    }
}

extension DeviceConsistencyMessage {

    /**
     The message serialized through a protocol buffer.
     - throws: `SignalError` of type `invalidProtoBuf`
     - returns: The serialized record of the message
     */
    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf,
                              "Could not serialize DeviceConsistencyMessage: \(error.localizedDescription)")
        }
    }

    /**
     Create a consistency message from a serialized protocol buffer record.
     - parameter data: The serialized data
     - parameter commitment: The commitment needed for verification
     - parameter identityKey: The identity key needed for verification
     - throws: `SignalError` errors
    */
    init(from data: Data, commitment: DeviceConsistencyCommitmentV0, identityKey: PublicKey) throws {
        let object: Signal_DeviceConsistencyCodeMessage
        do {
            object = try Signal_DeviceConsistencyCodeMessage(serializedData: data)
        } catch {
            throw SignalError(.invalidProtoBuf,
                              "Could not deserialize DeviceConsistencyMessage: \(error.localizedDescription)")
        }
        try self.init(from: object, commitment: commitment, identityKey: identityKey)
    }


}
