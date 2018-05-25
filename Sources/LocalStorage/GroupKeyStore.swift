//
//  GroupKeyStore.swift
//  SignalProtocol
//
//  Created by Christoph on 25.05.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation

public protocol GroupKeyStore: KeyStore {
    
    /// The type that distinguishes different groups and devices/users
    associatedtype GroupAddress: CustomStringConvertible

    /// The type of the sender key store
    associatedtype SenderKeyStoreType: SenderKeyStore where SenderKeyStoreType.Address == GroupAddress

    /// The Sender Key store that stores the records for the sender key module
    var senderKeyStore: SenderKeyStoreType { get }

}
