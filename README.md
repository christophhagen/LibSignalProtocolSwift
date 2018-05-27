# LibSignalProtocolSwift
A Swift implementation of the Signal Protocol. The [Signal Protocol](https://en.wikipedia.org/wiki/Signal_Protocol)
can be used for secure, end-to-end encrypted messaging in synchronous and asynchronous environments. It has
many desirable cryptographic features and can handle missing and out-of-order messages. The Signal protocol
is used by the [Signal Messenger](https://signal.org) as well as WhatsApp, Facebook, Skype and others. Additional
information can be found [here](https://signal.org/docs/).

## Purpose

This Swift library is intended for educational purposes only, in order to show the way the Signal Protocol works.
It somewhat mimics the functionality and structure of the [Signal Protocol C implementation](https://github.com/signalapp/libsignal-protocol-c).

## Installation

You can install `LibSignalProtocolSwift` through [Cocoapods](https://cocoapods.org), by adding the following to your `Podfile`:

````ruby
pod 'LibSignalProtocolSwift'
````

After installation the Framework can be accessed by importing it:

```swift
import SignalProtocol
```

## Prerequisites

### Local storage
The Signal Protocol needs local storage for message keys, identities and other state information.
You can provide this functionality by implementing the protocol `KeyStore`, which requires
four delegates for the individual data stores:

- `IdentityKeyStore` for storing and retrieving identity keys
- `PreKeyStore` for storing and retrieving pre keys
- `SessionStore` for storing and retrieving the sessions
- `SignedPreKeyStore` for storing and retrieving signed pre keys

#### Optional
There is a feature for group updates, where only one administrator can send, and the others can only receive. If you want this functionality, then implement the `GroupKeyStore` protocol, with the additional delegate  `SenderKeyStore` for storing and retrieving sender keys.

### Sample implementation

You can have a look at the [test implementation](https://github.com/christophhagen/LibSignalProtocolSwift/tree/master/Tests/Test%20Implementation) for inspiration.

### Server for message delivery
The server that stores the messages for retrieval needs to store the following data for each `SignalAddress`:
- `Public Identity Key`: The public part of the identity key of the device
- `Signed Pre Key`: The current signed pre key
- `Pre Keys`: A number of unsigned pre keys
- `Messages`: The messages to deliver to that address, including the sender

## Usage

The standard process to establish an encrypted session between two devices (two distinct `SignalAddress`es) is usually as follows:

- Alice uploads her `Identity`  and a `SignedPreKey` to the server, as well as a number of unsigned `PreKey`s.
- Bob retrieves a `PreKeyBundle` from the server, consisting of Alice's `Identity`, the `SignedPreKey`, and one of the `PreKey`s (which is then deleted from the server).
- Bob creates a session by processing the `PreKeyBundle` and encrypting a `PreKeyMessage` which he uploads to the server.
- Alice receives Bob's `PreKeyMessage` from the server and decryptes the message.
- The encrypted session is established for both Alice and Bob.

### Creating identity and keys

Before any secure communication can happen, at least one user needs to upload all necessary ingredients for a `PreKeyBundle` to the server.

````swift
// Create the identity key ata install time
let identity = try SignalCrypto.generateIdentityKeyPair()

// Store the data in the key store

// Get the public key from the store
let publicKey: Data = try bobStore.getPublicIdentityKey()

// Create pre keys and save them in the store
let preKeys: [Data] = try bobStore.createPreKeys(count: 10)

// Create a signed pre key and save it in the store
let signedPreKey: Data = try bobStore.updateSignedPrekey()

// Upload publicKey, preKeys, and signedPreKey to the server
````

### Creating a session from a PreKeyBundle

Let's assume that Alice (who has the `SignalAddress` aliceAddress) wants to establish a session with Bob (`SignalAddress` bobAddress)

````swift
// Download Bob's identity, current signedPreKey and one of the preKeys from the server

// Create PreKeyBundle
let preKeyBundle = try SessionPreKeyBundle(
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

#### Verifying identity Keys

To prevent man-in-the-middle attacks it can be beneficial to compare the identity keys either
by manually comparing the fingerprints or through scanning some sort of code (e.g. a QR-Code).
The library provides a convenient way for this:

```swift
// Create the fingerprint
let aliceFP = try aliceStore.fingerprint(for: bobAddress, localAddress: aliceAddress)

// Display the string...
let display = fingerprint.displayText

// ... or transmit the scannable data to the other client...
let scanData = try fingerprint.scannable.protoData()

// ... or compare to a received fingerprint
fingerprint.matches(scannedFingerprint)
```

### Miscellaneous

#### Client identifiers
The library is designed to allow different identifiers to distinguish between the different users.
The test implementation uses the `SignalAddress` struct for this, which consists of a `String` (e.g. a phone number)
and an `Int`, the `deviceId`. However it is possible to use different structs, classes, or types, as long as they
conform to the `Hashable`, `Equatable` and `CustomStringConvertible` protocols. For example, simple strings can be used:

```swift
class MyCustomKeyStore: KeyStore {

    typealias Address = String

    ...
}
```

Now, SessionCipher can be instantiated, using `MyCustomKeyStore` :

```swift
let aliceStore = MyCustomKeyStore()
let session = SessionCipher(store: aliceStore, remoteAddress: "Bob")
```

#### Providing a custom crypto implementation

It is possible for any custom implementation of the `SignalCryptoProvider` protocol
to serve as the cryptographic backbone of the protocol. This can be done by
setting the static `provider` variable of the `SignalCrypto` class:

```swift
SignalCrypto.provider = MyCustomCryptoProvider()
```

The elliptic curve functions are handled by the same C code that is deployed in
[libsignal-protocol-c](https://github.com/signalapp/libsignal-protocol-c)
and which is packaged in the [Curve25519](https://github.com/christophhagen/Curve25519)
framework to make the functions available in Swift.

#### Documentation

The project is documented heavily because it helps other people understand the code. The [documentation](https://github.com/christophhagen/SignalProtocolSwift/tree/master/Documentation)
is created with [jazzy](https://github.com/realm/jazzy), which creates awesome, apple-like
docs.

The docs can be (re-)generated by running the following in the project directory:
```
jazzy --min-acl private -a 'Christoph Hagen' -u 'https://github.com/christophhagen' -g 'https://github.com/christophhagen/LibSignalProtocolSwift' -e 'Sources/ProtocolBuffers/*' -o 'Documentation'
```

#### Disclaimer

This code is NOT intended for production use! The code is neither reviewed for errors
nor written by an expert. Please do not implement your own cryptographic software,
if you don't know EXACTLY what you are doing.
