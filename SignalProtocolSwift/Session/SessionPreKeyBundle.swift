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

}
