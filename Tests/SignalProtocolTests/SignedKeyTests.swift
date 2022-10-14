//
//  SignedKeyTests.swift
//  SignalProtocol Tests
//
//  Created by Christoph on 18.05.18.
//  Copyright © 2018 User. All rights reserved.
//

import XCTest
@testable import SignalProtocol


class SignedKeyTests: XCTestCase {
  
    func testSignedPreKey() {
        let key = try! KeyPair()
        let aliceStore = TestStore(with: try! key.protoData())
        
        guard let signedKeyData = try? aliceStore.updateSignedPrekey() else {
            XCTFail("Could not create signed pre key data")
            return
        }

        guard let signedKey = try? SessionSignedPreKeyPublic(from: signedKeyData) else {
            XCTFail("Could not create signed pre key")
            return
        }
        
        guard signedKey.verify(with: key.publicKey) else {
            XCTFail("Invalid signed key")
            return
        }
        
    }
    
}
