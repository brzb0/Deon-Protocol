# Deon Protocol v1.3.0

Deon Protocol is a **hybrid (BLE/Wi-Fi), offline-first, ultra-secure communication protocol** designed for IoT telemetry and heavy file transfer.

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

## Core Features

- **Hybrid Transport**: Uses BLE for discovery/handshake and small commands. Automatically switches to Wi-Fi TCP for payloads > 64KB (Smart Switching).
- **Security First**: 
  - **SPAKE2** for Password-Authenticated Key Exchange (PAKE) against MITM.
  - **ChaCha20-Poly1305** for AEAD encryption.
  - **Monotonic Nonces** to prevent replay attacks.
  - **Hardware-backed Key Storage** abstraction (Strongbox/Secure Enclave).
- **Resilience**: Exponential Back-off with Jitter for connection stability.
- **Efficiency**: `postcard` serialization for minimal overhead.

## CLI Usage

The Deon Protocol CLI supports sending and receiving files securely.

### Receive a File

Start the receiver on a specific port with a shared PIN.

```bash
./target/release/deon_protocol receive --port 8080 --password "123456"
```

### Send a File

Send a file to the receiver.

```bash
./target/release/deon_protocol send --file "document.pdf" --address "127.0.0.1:8080" --password "123456"
```

## Architecture

### 1. Protocol Stack

| Layer | Implementation |
|-------|----------------|
| **App** | Telemetry, File Transfer |
| **Protocol** | Deon State Machine (Searching, Handshaking, Streaming) |
| **Security** | SPAKE2 Handshake, AEAD Frames |
| **Transport** | `SecureTransport` Trait (BLE / TCP) |

### 2. Frame Structure

Every frame on the wire follows this structure:

```
[ Magic (2B) | Version (1B) | Flags (1B) | Nonce (12B) | Ciphertext (N) | Tag (16B) ]
```

- **Magic**: `0xDE01`
- **Nonce**: 96-bit unique counter (Monotonic).
- **Ciphertext**: Encrypted `postcard` serialized `ProtocolMessage`.

## Security Implementation

- **Key Management**: Keys are derived using SPAKE2. Master keys are protected by `KeyStorage` trait, intended to interface with Android Keystore/iOS Keychain.
- **Handover**: The Wi-Fi credentials are sent *encrypted* over the BLE link before switching.
- **Zeroize**: Sensitive keys are zeroed out from memory on drop.

## Requirements

- Rust 1.75+
- OpenSSL (if using default features of some crypto crates, though pure Rust implementations are preferred here).

## License

Apache License 2.0
