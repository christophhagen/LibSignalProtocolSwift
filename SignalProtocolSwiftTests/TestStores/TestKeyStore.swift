//
//  TestKeyStore.swift
//  TestC
//
//  Created by User on 21.09.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation
@testable import TestC

class TestKeyStore: KeyStoreDelegate {

    let identityKeyStore: IdentityKeyStoreDelegate

    let preKeyStore: PreKeyStoreDelegate

    let senderKeyStore: SenderKeyStoreDelegate

    let sessionStore: SessionStoreDelegate

    let signedPreKeyStore: SignedPreKeyStoreDelegate


    init?() {

        guard let identity = SignalInterface.generateIdentityKeyPair() else {
            print(#function + ": Could not create identity key")
            return nil
        }

        guard let registrationID = SignalInterface.generateRegistrationID() else {
            print(#function + ": Could not create local registration id")
            return nil
        }

        identityKeyStore = TestIdentityKeyStore(identity: identity, registrationID: registrationID)
        preKeyStore = TestPreKeyStore()
        senderKeyStore = TestSenderKeyStore()
        sessionStore = TestSessionStore()
        signedPreKeyStore = TestSignedPreKeyStore()
    }

}

