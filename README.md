# SignalProtocolSwift
A Swift wrapper to enable easy end-to-end message encryption with the Signal Protocol API.

This project provides a Swift wrapper to use [libsignal-protocol-c](https://github.com/WhisperSystems/libsignal-protocol-c) in Swift projects. It provides secure end-to-end encryption for asynchronous messaging applications. It's an open source protocol that is used by a variety of messengers, including WhatsApp and Facebook Messenger. It's also used the privacy-focused [Signal Messenger](https://signal.org) for iOS, Android and Desktop.

## What this project is

I created this wrapper because I wanted to use the Signal protocol for secure messaging, but using the C API in Swift is tedious. I wanted a very simple way to use the protocol, without having to think about the enryption stuff too much.

## What this project isn't

I'm not a cryptographer. I know some stuff that I read and taught myself, but I'm far from knowing enough to implement a the Signal Protocol securely. This code has not been reviewed by anyone, so please don't use it for anything except playing around. If you find anything wrong with the implementation, please let me know.

## Usage

### Prerequisites
The interaction with the API is pretty simple. All you need to do is implement the presistent storage for the keys and session data. This is done by implementing the protocols `IdentityKeyStoreDelegate`, `PreKeyStoreDelegate`, `SenderKeyStoreDelegate`, `SessionStoreDelegate`, and `SignedPreKeyStoreDelegate`. You don't have to know anything about the meaning of the data being stored.

The second thing you need is a server to store the encrypted messages and the keys needed to establish a session. The server stores:
- The encrypted messages to be delivered for each address.
- A Pre Key Bundle for each user (different for each address and device), which can be retrieved to establish a session.
- A number of Pre Keys for each user + device, which are needed besides the Pre Key Bundle to create a session.

All data shared with the server is just blobs of bytes. The server is simulated in the following example with the functions: `server.upload(bundle:for:)`, `server.upload(prekey:for:)`, `server.getSessionKeys(for:)`, `server.getMessage(for:)`, and server.upload(message:for:from:)`.

### Creating a session

All done? Great. Let's look at an example of Bob trying to establish a secure session with Alice.

#### Alice
```
/* First, Alice needs an address where she can be reached */
let aliceAddress = CHAddress(deviceID: 1, recipientID: "+12345678")!

/* Create the Interface for Alice */
let alice = SignalInterface(keyStore: TestKeyStore())!

/* Create a Pre Key Bundle */
let preKeyBundle = try! alice.generatePreKeyBundle(deviceID: aliceAddress.deviceID, signedPreKeyID: 12345)

/* Create a Pre Key */
let preKey = try! alice.generatePreKey()

/** Upload the Pre Key Bundle and Pre Key to the server for Alice's address */
server.upload(bundle: preKeyBundle, for: aliceAddress)
server.upload(prekey: preKey, for: aliceAddress)
```

#### Bob
```
/* Bob also needs an address */
let bobAddress = CHAddress(deviceID: 1, recipientID: "+23456789")!

/* Create the Interface for Alice */
let bob = SignalInterface(keyStore: TestKeyStore())!

/* Get the Pre Key bundle and one of the Pre Keys */
let (preKey, preKeybundle) = server.getSessionKeys(for: aliceAddress)

/* Encrypt an initial message */
let message = "Can you read this?"
let initialMessage = try! bob.encryptInitial(message, to: aliceAddress, with: preKeyBundle, and: preKey)

/* Upload the message to the server */
server.upload(message: initialMessage, for: aliceAddress, from: bobAddress)
```

#### Alice
```
/* get initial message from the server, assume we only get one message at a time */
let (initialMessage, bobAddress) = server.getMessage(for: aliceAddress)

/* Create session and decrypt message */
let decryptedMessage = try! alice.decrypt(message, from: bobAddress)
```

### Future messages

After this setup both Alice and Bob can send messages at will. For example:

#### Bob
```
/* Encrypt message */
let encryptedMessage = bob.encrypt(newMessage, for: aliceAddress)

/* Upload to the server */
server.upload(message: encryptedMessage, to: aliceAddress, from: bobAddress)
```

#### Alice
```
/* Get message from the server, assume we only get one message at a time */
let (encryptedMessage, bobAddress) = server.getMessage(for: aliceAddress)

/* Decrypt message */
let decryptedMessage = try! alice.decrypt(message, from: bobAddress)
```

### Identity change
If a session exists between two parties and one of the participants changes his/her identity key, then a new session has to be established by again using a Pre Key Bundle and a Pre Key. When trying to decrypt a message from the same sender with a different identity key, then the `decrypt(_:from:)` method will fail with an error of type `SignalErrorType.untrustedIdentity`. If you choose to trust the new identity simply modify the function call:

```
/* Decrypt message with changed identity key */
let decryptedMessage = try! alice.decrypt(message, from: bobAddress, trustNewIdentity: true)
```

## Future improvement
I'm working to make this module even easier to use. The things I want to do next:
- Handle the signed pre key ids internaly.
- Provide a protocol to implement the server functionality.
- Provide support for sending efficient messages to multiple recipients (group messaging)

Other stuff outside this library:
- Create a simple server (hopefully in Swift) to handle the server side
- Create a Core Data implementation for the key storage
- Create a second protocol layer for different message types
- Create a cool UI for messaging

## Contributing
If you find any errors, typos, unclear or missing documentation or possible improvements, create an issue or a pull request. Thanks!

## Legal stuff
Please use the software however you want, but be careful with it since it's not heavily tested. I'm not responsible for any damages caused by the use of this software. Also, don't be a dick and rip people off, and don't do anything illegal with it. Please don't disappoint me.
