# Deon Protocol v1.3.1

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

Deon Protocol is a **hybrid (BLE/Wi-Fi), offline-first, ultra-secure communication protocol** designed for IoT telemetry and heavy file transfer.

## Installation

Available on [Crates.io](https://crates.io/crates/deon_protocol).

### Binary (CLI)
Install the command-line tool globally:
```bash
cargo install deon_protocol
```

### Library
Add it to your project dependencies:
```bash
cargo add deon_protocol
```
Or add this to your `Cargo.toml`:
```toml
deon_protocol = "1.3.2"
```

## Core Features

- **Hybrid Transport**: Uses BLE for discovery/handshake and small commands. Automatically switches to Wi-Fi TCP for payloads > 64KB (Smart Switching).
- **Security First**: 
  - **X25519** for Ephemeral Key Exchange.
  - **ChaCha20-Poly1305** for AEAD encryption.
  - **Monotonic Nonces** to prevent replay attacks.
  - **Hardware-backed Key Storage** abstraction (Strongbox/Secure Enclave).
- **Resilience**: Exponential Back-off with Jitter for connection stability.
- **Efficiency**: `postcard` serialization for minimal overhead.

## Architecture

### 1. Protocol Stack

| Layer | Implementation |
|-------|----------------|
| **App** | Telemetry, File Transfer |
| **Protocol** | Deon State Machine (Searching, Handshaking, Streaming) |
| **Security** | Noise-like Handshake (PAKE), AEAD Frames |
| **Transport** | `SecureTransport` Trait (BLE / TCP) |

### 2. Frame Structure

Every frame on the wire follows this structure:

```
[ Magic (2B) | Version (1B) | Flags (1B) | Nonce (12B) | Ciphertext (N) | Tag (16B) ]
```

- **Magic**: `0xDE01`
- **Nonce**: 96-bit unique counter (Monotonic).
- **Ciphertext**: Encrypted `postcard` serialized `ProtocolMessage`.

### 3. Usage

```rust
use deon_protocol::{DeonProtocol, TcpTransport}; // Updated for v1.3.0 CLI usage

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example usage
    let transport = deon_protocol::transport::connect_tcp("127.0.0.1:8080").await?;
    let mut deon = DeonProtocol::new(transport);
    
    // Handshake
    deon.handshake("123456").await?;
    
    // Send Data
    let large_file = vec![0u8; 100_000];
    deon.send_file("update.bin", &large_file).await?;
    
    Ok(())
}
```

## Security Implementation

- **Key Management**: Keys are derived using HKDF-SHA256. Master keys are protected by `KeyStorage` trait, intended to interface with Android Keystore/iOS Keychain.
- **Handover**: The Wi-Fi credentials are sent *encrypted* over the BLE link before switching.
- **Zeroize**: Sensitive keys are zeroed out from memory on drop.

## Requirements

- Rust 1.75+
- OpenSSL (if using default features of some crypto crates, though pure Rust implementations are preferred here).

## License

Apache License 2.0
