# SignalProtocolSwift
A Swift implementation of the Signal Protocol. The [Signal Protocol](https://en.wikipedia.org/wiki/Signal_Protocol)
can be used for secure, end-to-end encrypted messaging in synchronous and asynchronous environments. It has
many desirable cryptographic features and can handle missing and out-of-order messages. The Signal protocol
is used by the [Signal Messenger](signal.org) as well as WhatsApp, Facebook, Skype and others. Additional
information can be found [here](https://signal.org/docs/).

## Purpose

This Swift library is intended for educational purposes only, in order to show the way the Signal Protocol works.
It mimics the functionality and structure of the [Signal Protocol C implementation](https://github.com/signalapp/libsignal-protocol-c).

## Installation

You can install `SignalProtocolSwift` through [Cocoapods](https://cocoapods.org), by adding the following to your `Podfile`:

````ruby
pod 'SignalProtocolSwift', :git => 'https://github.com/christophhagen/SignalProtocolSwift'
````

[Curve25519](https://github.com/christophhagen/Curve25519) is my framework to use the elliptic curve functions in Swift.

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
- `Signed Pre Key Data`: The current signed pre key
- `Pre Keys`: A number of unsigned pre keys
- `Messages`: The messages to deliver

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
let preKeys: [Data] = try bobStore.createPreKeys(start: 1, count: 10)

// Create a signed pre key and save it in the store
let signedPreKey: Data = try bobStore.createSignedPrekey(id: 1)

// Upload identity, preKeys, and signedPreKey to the server
````

### Creating a session from a PreKeyBundle

Let's assume that Alice (who has the `SignalAddress` aliceAddress) wants to establish a session with Bob (`SignalAddress` bobAddress)

````swift
// Download Bob's identity, current signedPreKey and one of the preKeys from the server

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
````

### Using an already established session
Now Alice and Bob can both send and receive messages at will.

#### Sending

```swift
// Compose a message
let message =  "Hello there".data(using: .utf8)!

// Encrypt
let encryptedMessage = try session.encrypt(message)
```

#### Receiving

```swift
// Get message from the server

// Decrypt
let decryptedMessage = try session.decrypt(message)
```

### Miscellaneous

#### Provide custom crypto implementation

It is possible for any custom implementation of the `SignalCryptoProvider` protocol
to serve as the cryptographic backbone of the protocol. This can be done by
setting the static `provider` variable of the `SignalCrypto` class.

#### Documentation

The project is documented heavily because it helps other people understand the code. The [documentation](https://github.com/christophhagen/SignalProtocolSwift/tree/master/Documentation)
is created with [jazzy](https://github.com/realm/jazzy), which creates awesome, apple-like
docs.

The docs can be (re-)generated by running the following in the project directory:
```
jazzy --min-acl private -a 'Christoph Hagen' -u 'https://github.com/christophhagen' -g 'https://github.com/christophhagen/SignalProtocolSwift' -e 'SignalProtocolSwift/ProtocolBuffers/*' -o 'Documentation'
```

#### Disclaimer

This code is NOT intended for production use! The code is neither reviewed for errors
nor written by an expert. Please do not implement your own cryptographic software,
if you don't know EXACTLY what you are doing.
