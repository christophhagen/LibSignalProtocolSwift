//
//  PendingPreKey.swift
//  libsignal-protocol-swift
//
//  Created by User on 12.10.17.
//  Copyright © 2017 User. All rights reserved.
//

import Foundation

struct PendingPreKey {

    var preKeyId: UInt32?

    var signedPreKeyId: UInt32

    var baseKey: PublicKey

}

extension PendingPreKey {
    
    init(serializedObject object: Textsecure_SessionStructure.PendingPreKey) throws {
        guard object.hasBaseKey, object.hasSignedPreKeyID else {
            throw SignalError(.invalidProtoBuf, "Missing data in object")
        }
        if object.hasPreKeyID {
            self.preKeyId = object.preKeyID
        }
        if object.signedPreKeyID < 0 {
            throw SignalError(.invalidProtoBuf, "Invalid SignedPreKey id \(object.signedPreKeyID)")
        }
        self.signedPreKeyId = UInt32(object.signedPreKeyID)
        self.baseKey = try PublicKey(from: object.baseKey)
    }

    init(from data: Data) throws {
        do {
            let object = try Textsecure_SessionStructure.PendingPreKey(serializedData: data)
            try self.init(serializedObject: object)
        } catch {
            throw SignalError(.invalidProtoBuf,
                              "Could not deserialize PendingPreKey: \(error.localizedDescription)")
        }
    }

    func data() throws -> Data {
        do {
            return try object.serializedData()
        } catch {
            throw SignalError(.invalidProtoBuf,
                              "Could not serialize PendingPreKey: \(error.localizedDescription)")
        }
    }

    var object: Textsecure_SessionStructure.PendingPreKey {
        return Textsecure_SessionStructure.PendingPreKey.with {
            if let item = preKeyId {
                $0.preKeyID = item
            }
            $0.signedPreKeyID = Int32(self.signedPreKeyId)
            $0.baseKey = self.baseKey.data
        }
    }
}

extension PendingPreKey: Equatable {
    static func ==(lhs: PendingPreKey, rhs: PendingPreKey) -> Bool {
        return lhs.preKeyId == rhs.preKeyId &&
            lhs.signedPreKeyId == rhs.signedPreKeyId &&
            lhs.baseKey == rhs.baseKey
    }
}
