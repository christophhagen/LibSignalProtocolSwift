//
//  Identity.swift
//  TestC
//
//  Created by User on 25.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Relays the callbacks of the Signal API to the delegate responsible for persistent store
 */
class IdentityKeyStore {

    /// The delegate handling persistent storage
    let delegate: IdentityKeyStoreDelegate

    /// Store the registration ID for the callback
    fileprivate var registrationID: UInt32 = 0

    /// The context needed to register the callbacks
    private let storeContext: OpaquePointer

    /**
     Initialize the identity key store with the context. Will be called when a
     `KeyStore` is created.

     - parameter context: The protocol store context
     - parameter delegate: The delegate that handles the calls
     */
    init?(with context: OpaquePointer, delegate: IdentityKeyStoreDelegate) {
        storeContext = context
        self.delegate = delegate

        var functions = signal_protocol_identity_key_store(get_identity_key_pair: getIdentityKeyPair,
                                                           get_local_registration_id: getLocalRegistrationID,
                                                           save_identity: saveIdentity,
                                                           is_trusted_identity: isTrustedIdentity,
                                                           destroy_func: destroy,
                                                           user_data: pointer(obj: self))

        let result = withUnsafePointer(to: &functions) { pointer in
            return signal_protocol_store_context_set_identity_key_store(storeContext, pointer)
        }
        guard result == 0 else {
            return nil
        }
    }
}
/**
 Get the local client's identity key pair.

 - parameter publicData: pointer to a newly allocated buffer containing the public key, if found. Unset if no record was found. The Signal Protocol library is responsible for freeing this buffer.
 - parameter privateData: pointer to a newly allocated buffer containing the private key, if found. Unset if no record was found. The Signal Protocol library is responsible for freeing this buffer.
 - parameter userData: Pointer to the responsible instance
 - returns: 0 on success, negative on failure
 */
private func getIdentityKeyPair(publicData: UnsafeMutablePointer<UnsafeMutablePointer<signal_buffer>?>?,
                                   privateData: UnsafeMutablePointer<UnsafeMutablePointer<signal_buffer>?>?,
                                   userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let store: IdentityKeyStore = instance(for: userData) else {
        return -1
    }
    guard let key = store.delegate.identityKey else {
        return -1
    }

    var identityKeyPair: OpaquePointer? = nil
    var result = withUnsafeMutablePointer(to: &identityKeyPair) { (pointer: UnsafeMutablePointer<OpaquePointer?>) -> Int32 in
        return ratchet_identity_key_pair_deserialize(pointer, UnsafePointer(key), key.count, SignalInterface.context)
    }
    guard result == 0 else {
        return result
    }

    let publicKey = ratchet_identity_key_pair_get_public(identityKeyPair);
    result = ec_public_key_serialize(publicData, publicKey);
    guard (result == 0) else {
        ratchet_identity_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(identityKeyPair))
        return -1;
    }

    let privateKey = ratchet_identity_key_pair_get_private(identityKeyPair);
    result = ec_private_key_serialize(privateData, privateKey);
    guard (result == 0) else {
        ratchet_identity_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(identityKeyPair))
        return -1;
    }
    
    ratchet_identity_key_pair_destroy(UnsafeMutablePointer<signal_type_base>(identityKeyPair))
    return 0
}

/**
 Return the local client's registration ID.

 Clients should maintain a registration ID, a random number between 1 and 16380 that's generated once at install time.

 - parameter userData: Pointer to the responsible instance
 - parameter registrationID: A pointer to be set to the registrationID
 - returns: The local registration ID, or 0 if it doesn't exist
 */
private func getLocalRegistrationID(userData: UnsafeMutableRawPointer?,
                                       registrationID: UnsafeMutablePointer<UInt32>?) -> Int32 {
    guard let store: IdentityKeyStore = instance(for: userData) else {
        return -1
    }
    guard registrationID != nil else {
        return -1
    }
    let id = store.delegate.localRegistrationID
    guard 1 ... 16380 ~= id else {
        return -1
    }

    store.registrationID = UInt32(id)
    registrationID!.pointee = store.registrationID
    return 0
}

/**
 Save a remote client's identity key.

 Store a remote client's identity key as trusted. The value of key_data may be null. In this case remove the key data from the identity store, but retain any metadata that may be kept alongside it.

 - Parameters:
 - address: A pointer to the address for which the key will be saved
 - data: Pointer to the data to be saved
 - length: The length of the data
 - userData: Pointer to the responsible instance
 - returns: 0 on success, negative on failure
 */
private func saveIdentity(address: UnsafePointer<signal_protocol_address>?,
                           data: UnsafeMutablePointer<UInt8>?,
                           length: Int,
                           userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let (convertedAddress, record) = convert(address, data: data, length: length) else {
        return -1
    }

    guard let store: IdentityKeyStore = instance(for: userData) else {
        return -1
    }
    return Int32(store.delegate.saveIdentity(for: convertedAddress, and: record) ? 0 : -1)
}

/**
 Verify a remote client's identity key.

 Determine whether a remote client's identity is trusted.  Convention is that the TextSecure protocol is 'trust on first use.' This means that an identity key is considered 'trusted' if there is no entry for the recipient in the local store, or if it matches the saved key for a recipient in the local store. Only if it mismatches an entry in the local store is it considered 'untrusted.'

 - Parameters:
 - address: A pointer to the address for which the key is checked
 - data: Pointer to the data to be checked
 - length: The length of the data
 - userData: Pointer to the responsible instance
 - returns: 1 if the device is trusted, 0 if untrusted, negative on error
 */
private func isTrustedIdentity(address: UnsafePointer<signal_protocol_address>?,
                                 data: UnsafeMutablePointer<UInt8>?,
                                 length: Int,
                                 userData: UnsafeMutableRawPointer?) -> Int32 {
    guard let (convertedAddress, record) = convert(address, data: data, length: length) else {
        return -1
    }
    guard let store: IdentityKeyStore = instance(for: userData) else {
        return -1
    }
    return store.delegate.isTrustedIdentity(for: convertedAddress, and: record) == true ? 1 : 0
}

/**
 Function called to perform cleanup when the data store context is being destroyed.

 - parameter userData: A void pointer to the instance that is responsible for the call
 */
private func destroy(userData: UnsafeMutableRawPointer?) {
    guard let store: IdentityKeyStore = instance(for: userData) else {
        return
    }
    store.delegate.cleanup()
}

/**
 Convert address and data pointers to Swift types
 */
private func convert(_ address: UnsafePointer<signal_protocol_address>?, data: UnsafeMutablePointer<UInt8>?, length: Int) -> (CHAddress, [UInt8]?)? {
    guard let convertedAddress = CHAddress(from: address) else {
        return nil
    }

    if let start = data {
        let record = Array(UnsafeMutableBufferPointer(start: start, count: length))
        return (convertedAddress, record)
    }
    return (convertedAddress, nil)
}

