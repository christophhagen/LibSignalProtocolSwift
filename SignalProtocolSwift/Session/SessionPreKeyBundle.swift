//
//  SessionPreKeyBundle.swift
//  libsignal-protocol-swift
//
//  Created by User on 25.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

public struct SessionPreKeyBundle {

    var registrationId: UInt32

    var deviceId: UInt32

    var preKeyId: UInt32

    var preKeyPublic: PublicKey?

    var signedPreKeyId: UInt32

    var signedPreKeyPublic: PublicKey

    var signedPreKeySignature: Data

    var identityKey: PublicKey

    public init(
        registrationId: UInt32,
        deviceId: UInt32,
        preKeyId: UInt32,
        preKeyPublic: PublicKey?,
        signedPreKeyId: UInt32,
        signedPreKeyPublic: PublicKey,
        signedPreKeySignature: Data,
        identityKey: PublicKey) {

        self.registrationId = registrationId
        self.deviceId = deviceId
        self.preKeyId = preKeyId
        self.preKeyPublic = preKeyPublic
        self.signedPreKeyId = signedPreKeyId
        self.signedPreKeyPublic = signedPreKeyPublic
        self.signedPreKeySignature = signedPreKeySignature
        self.identityKey = identityKey
    }

}
