//
//  SignalServer.swift
//  SignalCommunication-iOS
//
//  Created by User on 15.11.17.
//

import Foundation

protocol SignalServer {

    var ownAddress: SignalAddress { get }

    /**
     Initialize the server with the sending address and the signature
     key used to authenticate the user.
    */
    init(ownAddress: SignalAddress, signatureKey: PrivateKey)

    /**
     Store the identity of the local client on the server.
     - parameter identity: The new identity to upload.
    */
    func upload(identity: PreKeyBundle.Identity) throws

    /**
     Store a new SignedPreKey on the server (deleting the old one).
     - Note: A new key should be uploaded every few days.
     - parameter signedPreKey: The new key to upload
     - returns: `True` on success
    */
    func upload(signedPreKey: PreKeyBundle.SignedPreKey) throws

    /**
     Store a number of unsigned PreKeys on the server.
     - Note: These keys should be replenished as needed.
     - parameter preKeys: The keys to upload.
     - returns: `True` on success
     */
    func upload(preKeys: [PreKeyBundle.PreKey]) throws

    /**
     Get the number of remaining PreKeys on the server
     */
    func preKeyCount() throws -> Int

    /**
     Retrieve all messages from the server.
     - returns: A dictionary of the messages indexed by the sender address.
     - throws: Errors if the messages can't be retrieved
     */
    func messages() throws -> [SignalAddress : [Data]]

    /**
     Retrieve all messages from a specific sender.
     - returns: The messages from the sender as an array.
     - throws: Errors if the messages can't be retrieved
    */
    func messages(from sender: SignalAddress) throws -> [Data]

    /**
     Upload a message to a recipient.
     - parameter message: The message to upload
     - parameter receiver: The intended recipient of the message
     - returns: `True` on success
    */
    func upload(message: Data, for receiver: SignalAddress) throws

    /**
     Upload messages to a recipient.
     - parameter messages: The messages to upload
     - parameter receiver: The intended recipient of the messages
     - returns: `True` on success
     */
    func upload(messages: [Data], for receiver: SignalAddress) throws

    /**
     Get a PreKeyBundle to create a new session with another client.
     - parameter address: The remote address for which to get the bundle.
     - returns: The PreKeyBundle for the recipient.
    */
    func preKeyBundle(for address: SignalAddress) throws -> PreKeyBundle
}
