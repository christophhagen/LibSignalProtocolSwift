//
//  DeviceConsistencyTests.swift
//  libsignal-protocol-swiftTests
//
//  Created by User on 10.11.17.
//  Copyright © 2017 User. All rights reserved.
//

import XCTest
@testable import SignalProtocolSwift

class DeviceConsistencyTests: XCTestCase {

    func testDeviceConsistency() {
        /* Create three device key pairs */
        guard let deviceOne = try? KeyPair(),
            let deviceTwo = try? KeyPair(),
            let deviceThree = try? KeyPair() else {
                XCTFail("Could not create keys")
                return
        }
        var keyArray = [deviceOne.publicKey, deviceTwo.publicKey, deviceThree.publicKey]

        /* Create device one commitment */
        shuffle(&keyArray)
        guard let deviceOneCommitment = try? DeviceConsistencyCommitmentV0(generation: 1, identityKeyList: keyArray) else {
            XCTFail("Could not create first commitment")
            return
        }

        /* Create device two commitment */
        shuffle(&keyArray)
        guard let deviceTwoCommitment = try? DeviceConsistencyCommitmentV0(generation: 1, identityKeyList: keyArray) else {
            XCTFail("Could not create second commitment")
            return
        }

        /* Create device three commitment */
        shuffle(&keyArray)
        guard let deviceThreeCommitment = try? DeviceConsistencyCommitmentV0(generation: 1, identityKeyList: keyArray) else {
            XCTFail("Could not create third commitment")
            return
        }

        guard deviceOneCommitment.serialized == deviceTwoCommitment.serialized,
            deviceTwoCommitment.serialized == deviceThreeCommitment.serialized else {
            XCTFail("Commitments aren't equal")
            return
        }

        /* Create device consistency messages */
        guard let deviceOneMessage = try? DeviceConsistencyMessage(commitment: deviceOneCommitment, identitykeyPair: deviceOne),
            let deviceTwoMessage = try? DeviceConsistencyMessage(commitment: deviceTwoCommitment, identitykeyPair: deviceTwo),
            let deviceThreeMessage = try? DeviceConsistencyMessage(commitment: deviceThreeCommitment, identitykeyPair: deviceThree) else {
                XCTFail("Could not create DeviceConsistencyMessages")
                return
        }

        /* Create received device consistency messages */
        guard let receivedDeviceOneMessage = try? DeviceConsistencyMessage(
            from: try deviceOneMessage.data(),
            commitment: deviceOneCommitment,
            identityKey: deviceOne.publicKey) else {
                XCTFail("Could not create received message one")
                return
        }

        guard let receivedDeviceTwoMessage = try? DeviceConsistencyMessage(
            from: try deviceTwoMessage.data(),
            commitment: deviceTwoCommitment,
            identityKey: deviceTwo.publicKey) else {
                XCTFail("Could not create received message two")
                return
        }

        guard let receivedDeviceThreeMessage = try? DeviceConsistencyMessage(
            from: try deviceThreeMessage.data(),
            commitment: deviceThreeCommitment,
            identityKey: deviceThree.publicKey) else {
                XCTFail("Could not create received message three")
                return
        }

        /* Check that all sent-and-received pairs have the same VRF output */
        guard deviceOneMessage.signature.vrfOutput == receivedDeviceOneMessage.signature.vrfOutput else {
            XCTFail("VRF output mismatch for device one")
            return
        }
        guard deviceTwoMessage.signature.vrfOutput == receivedDeviceTwoMessage.signature.vrfOutput else {
            XCTFail("VRF output mismatch for device one")
            return
        }
        guard deviceThreeMessage.signature.vrfOutput == receivedDeviceThreeMessage.signature.vrfOutput else {
            XCTFail("VRF output mismatch for device one")
            return
        }

        /* Generate consistency codes */
        guard let codeOne = try? generateCode(
            commitment: deviceOneCommitment,
            message1: deviceOneMessage,
            message2: receivedDeviceTwoMessage,
            message3: receivedDeviceThreeMessage) else {
                XCTFail("Could not generate code one")
                return
        }
        guard let codeTwo = try? generateCode(
            commitment: deviceOneCommitment,
            message1: deviceTwoMessage,
            message2: receivedDeviceThreeMessage,
            message3: receivedDeviceOneMessage) else {
                XCTFail("Could not generate code two")
                return
        }
        guard let codeThree = try? generateCode(
            commitment: deviceOneCommitment,
            message1: deviceThreeMessage,
            message2: receivedDeviceTwoMessage,
            message3: receivedDeviceOneMessage) else {
                XCTFail("Could not generate code three")
                return
        }

        /* Check that all the consistency codes match */
        guard codeOne == codeTwo, codeTwo == codeThree else {
            XCTFail("Codes don't match")
            return
        }
    }

    private func generateCode(
        commitment: DeviceConsistencyCommitmentV0,
        message1: DeviceConsistencyMessage,
        message2: DeviceConsistencyMessage,
        message3: DeviceConsistencyMessage) throws -> String {

        /* Build the list of signatures */
        let list = [message1.signature, message2.signature, message3.signature]

        return try commitment.generateCode(for: list)
    }
}
