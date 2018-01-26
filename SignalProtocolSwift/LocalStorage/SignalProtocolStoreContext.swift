//
//  SignalProtocolStoreContext.swift
//  SignalProtocolSwift
//
//  Created by User on 01.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation


/**
 Provide all local storage delegates.
 */
public protocol SignalProtocolStoreContext {

    associatedtype Address

    associatedtype GroupAddress

    associatedtype IdentityKeyStore: IdentityKeyStoreDelegate where IdentityKeyStore.Address == Address

    associatedtype SenderKeyStore: SenderKeyStoreDelegate where SenderKeyStore.Address == GroupAddress

    associatedtype SessionStore: SessionStoreDelegate where SessionStore.Address == Address

    /// The Identity Key store that stores the records for the identity key module
    var identityKeyStore: IdentityKeyStore { get }

    /// The Pre Key store that stores the records for the pre key module
    var preKeyStore: PreKeyStoreDelegate { get }

    /// The Sender Key store that stores the records for the sender key module
    var senderKeyStore: SenderKeyStore { get }

    /// The Session store that stores the records for the session module
    var sessionStore: SessionStore { get }

    /// The Signed Pre Key store that stores the records for the signed pre key module
    var signedPreKeyStore: SignedPreKeyStoreDelegate { get }

}
