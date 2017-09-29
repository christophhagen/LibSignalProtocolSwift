//
//  KeyStore.swift
//  TestC
//
//  Created by User on 28.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

/**
 Provide all storage delegates when creating a new `SignalInterface`.
 Classes implementing this protocol can use `SignalInterface.init(keyStore:)`.
 It is also possible to provide each delegate separately.
 */
protocol KeyStoreDelegate {

    /// The Identity Key store that stores the records for the identity key module
    var identityKeyStore: IdentityKeyStoreDelegate { get }

    /// The Pre Key store that stores the records for the pre key module
    var preKeyStore: PreKeyStoreDelegate { get }

    /// The Sender Key store that stores the records for the sender key module
    var senderKeyStore: SenderKeyStoreDelegate { get }

    /// The Session store that stores the records for the session module
    var sessionStore: SessionStoreDelegate { get }

    /// The Signed Pre Key store that stores the records for the signed pre key module
    var signedPreKeyStore: SignedPreKeyStoreDelegate { get }
    
}
