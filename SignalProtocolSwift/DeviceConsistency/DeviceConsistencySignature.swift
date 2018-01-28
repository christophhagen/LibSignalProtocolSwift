//
//  DeviceConsistencySignature.swift
//  SignalProtocolSwift-iOS
//
//  Created by User on 18.11.17.
//

import Foundation

/**
 A signature used for device consistency checks
 */
struct DeviceConsistencySignature {

    /// The signature data
    var signature: Data

    /// The output of the VRF verification
    var vrfOutput: Data

    /**
     Create a new signature
     - parameter signature: The signature data
     - parameter vrfOutput: The output of the VRF verification
    */
    init(signature: Data, vrfOutput: Data) {
        self.signature = signature
        self.vrfOutput = vrfOutput
    }
}

extension DeviceConsistencySignature: Comparable {
    
    /**
     Compare two consistency signatures.
     - note: The signatures are compared solely by their vrf outputs
     - parameter lhs: The first signature
     - parameter rhs: The second signature
     - returns: `True`, if the first signature is 'smaller' than the second signature
    */
    static func <(lhs: DeviceConsistencySignature, rhs: DeviceConsistencySignature) -> Bool {
        guard lhs.vrfOutput.count == rhs.vrfOutput.count else {
            return lhs.vrfOutput.count < rhs.vrfOutput.count
        }
        for i in 0..<lhs.vrfOutput.count {
            if lhs.vrfOutput[i] != rhs.vrfOutput[i] {
                return lhs.vrfOutput[i] < rhs.vrfOutput[i]
            }
        }
        return false
    }

    /**
     Compare two consistency signatures for equality.
     - note: The signatures are compared solely by their vrf outputs
     - parameter lhs: The first signature
     - parameter rhs: The second signature
     - returns: `True`, if the signature vrf outputs are equal
     */
    static func ==(lhs: DeviceConsistencySignature, rhs: DeviceConsistencySignature) -> Bool {
        return lhs.vrfOutput == rhs.vrfOutput
    }
}
