# SignalProtocolSwift
A Swift implementation of the Signal Protocol API (libsignal-protocol-c)

## Purpose

This Swift library is intended for educational purposes only, in order to show the way the Signal Protocol works.

## Installation

You can install `SignalProtocolSwift` through [Cocoapods](https://cocoapods.org), by adding the following to your `Podfile`:

````ruby
pod 'SignalProtocolSwift', :git => 'https://github.com/christophhagen/SignalProtocolSwift'
pod 'Curve25519', :git => 'https://github.com/christophhagen/Curve25519'
````

`Curve25519` is my framework to use the elliptic curve functions in Swift.

## Prerequisites

### Local storage
The Signal Protocol needs local storage for message keys, identities and other state information. You can provide this functionality by implementing the protocol `SignalProtocolStoreContext`, which requires five delegates for the individual data stores:
- `IdentityKeyStoreDelegate` for storing and retrieving identity keys
- `PreKeyStoreDelegate` for storing and retrieving pre keys
- `SenderKeyStoreDelegate` for storing and retrieving sender keys
- `SessionStoreDelegate` for storing and retrieving the sessions
- `SignedPreKeyStoreDelegate` for storing and retrieving signed pre keys

You can have a look at the [test implementation](https://github.com/christophhagen/SignalProtocolSwift/tree/master/SignalProtocolSwiftTests/Test%20Implementation) for inspiration.

### Server for message delivery
The server that stores the messages for retrieval needs to store the following data for each `SignalAddress`:
- `Public Identity Key Data`: The public part of the identity key of the device
- `Signed Pre Key`: The current signed pre key
- `Pre Keys`: A number of unsigned pre keys
- `Messages`: The new messages to deliver

## Usage

The standard process to establish an encrypted session between two devices (two distinct `SignalAddress`es) is usually as follows:

- Alice uploads her `Identity` (`PublicKey`, `deviceId` and `registrationId`) and a `SignedPreKey` to the server, as well as a number of unsigned `PreKey`s.
- Bob retrieves a `PreKeyBundle` from the server, consisting of Alice's `Identity`, the `SignedPreKey`, and one of the `PreKey`s (which is then deleted from the server).
- Bob creates a session by processing the `PreKeyBundle` and encrypting a `PreKeyMessage` which he uploads to the server.
- Alice receives Bob's `PreKeyMessage` from the server and decryptes the message.
- The encrypted session is established for both Alice and Bob.

### Creating identity and keys

Before any secure communication can happen, at least one user needs to upload all necessary ingredients for a `PreKeyBundle` to the server.

````swift
// Create the identity key and store it (only done once)
let identity: Data = try bobStore.createIdentityKey()

// Create pre keys and save them in the store
let preKeys: Data = try bobStore.createPreKeys(start: 1, count: 10)

// Create a signed pre key and save it in the store
let signedPreKey: Data = try bobStore.createSignedPrekey(id: 1)

// Upload identity, preKeys, and signedPreKey to the server
````

### Creating a session from a PreKeyBundle

Let's assume that Alice (who has the `SignalAddress` aliceAddress) wants to establish a session with Bob (`SignalAddress` bobAddress)

````swift
// Download Bob's identity, preKey, and signedPreKey from the server

// Create PreKeyBundle
let preKeyBundle = try SessionPreKeyBundle(
    registrationId: 0, // Not used
    deviceId: bobAddress.deviceId,
    preKey: preKey,
    signedPreKey: signedPreKey,
    identityKey: identity)

// Create a new session by processing the PreKeyBundle
let session = SessionCipher(store: aliceStore, remoteAddress: bobAddress)
try session.process(preKeyBundle: preKeyBundle)

// The message to encrypt
let message = "Hello Bob, it's Alice".data(using: .utf8)!

// Here Alice can send messages to Bob
let encryptedMessage = try session.encrypt(message)

// Upload the message to the server
````

### Creating a session from a received PreKeySignalMessage
Let's continue the above example and assume Bob receives the message from Alice. Bob can then establish the session:

````swift
// Get the message from the server

// Create the session
let session = Session(for: aliceAddress)

// Process the message
let decryptedMessage = try session.decrypt(preKeyMessage)

// Write a reply
let replyMessage =  "Hello Alice, it's Bob".data(using: .utf8)

// Bob can now encrypt messages to Alice
let encryptedMessage = try session.encrypt(string: message)

// Upload the message to the server
````

### Using an already established session
Now Alice can receive Bob's messages:

````swift
// Get each message from the server

// Decrypt each message
let decryptedMessage = try session.decrypt(message)
````

Or send her own:

````swift
// Create the session to use
let session = Session(for: bobAddress)

// Create the message
let message = "Hello Bob, I received your message".data(using: .utf8)

// Send a message
let encryptedMessage = try session.encrypt(message)

// Upload the message to the server
````

### Miscellaneous

#### Generate docs:

Run in project root:
`jazzy --min-acl private -a 'Christoph Hagen' -u 'https://github.com/christophhagen' -g 'https://github.com/christophhagen/SignalProtocolSwift'`
