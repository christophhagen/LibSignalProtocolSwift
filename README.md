# SignalProtocolSwift
A Swift implementation of the Signal Protocol API (libsignal-protocol-c)

## Purpose

This Swift library is intended for educational purposes only, in order to show the way the Signal Protocol works.

## Prerequisites

### Local storage
The Signal Protocol needs local storage for message keys, identities and other state information. You can provide this functionality by implementing the protocol `SignalProtocolStoreContext`, which requires five delegates for the individual data stores:
- `IdentityKeyStoreDelegate` for storing and retrieving identity keys
- `PreKeyStoreDelegate` for storing and retrieving pre keys
- `SenderKeyStoreDelegate` for storing and retrieving sender keys
- `SessionStoreDelegate` for storing and retrieving the sessions
- `SignedPreKeyStoreDelegate` for storing and retrieving signed pre keys

### Server for message delivery
The server that stores the messages for retrieval needs to store the following data for each `SignalAddress`:
- `IdentityKeyPublicData`: The public part of the identity key of the device
- `SignedPreKeyData`: The current signed pre key
- `PreKeyData`: A number of unsigned pre keys
- `Messages`: The new messages to deliver

## Usage

The standard process to establish an encrypted session between two devices (two distinct `SignalAddress`es) is usually as follows:

- Alice uploads her `Identity` (`PublicKey`, `deviceId` and `registrationId`) and a `SignedPreKey` to the server, as well as a number of unsigned `PreKey`s.
- Bob retrieves a `PreKeyBundle` from the server, consisting of Alice's `Identity`, the `SignedPreKey`, and one of the `PreKey`s (which is then deleted from the server).
- Bob creates a session by processing the `PreKeyBundle` and encrypting a `PreKeyMessage` which he uploads to the server.
- Alice receives Bob's `PreKeyMessage` from the server and decryptes the message.
- The encrypted session is established for both Alice and Bob.

### Creating a session from a PreKeyBundle

Let's assume that Alice (who has the `SignalAddress` aliceAddress) wants to establish a session with Bob (`SignalAddress` bobAddress)
````swift
// Download the PreKeyBundle from the server

// Create a new session by processing the downloaded PreKeyBundle
let session = try Session(for: bobAddress, with: preKeyBundle)

// The message to encrypt
let message = "Hello Bob, it's Alice".data(using: .utf8)
  
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
// Get each messages from the server

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
