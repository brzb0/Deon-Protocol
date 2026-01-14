# Deon Protocol v1.3.3

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

Deon Protocol is a **hybrid (BLE/Wi-Fi), offline-first, ultra-secure communication protocol** designed for IoT telemetry, heavy file transfer, and offline value exchange.

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
deon_protocol = "1.3.3"
```

## Core Features

- **Hybrid Transport**: Uses BLE for discovery/handshake and small commands. Automatically switches to Wi-Fi TCP for payloads > 64KB (Smart Switching).
- **Security First**: 
  - **X25519** for Ephemeral Key Exchange.
  - **XChaCha20-Poly1305** (24-byte nonce) for AEAD encryption.
  - **Replay Protection** via random nonces (Transport) and monotonic nonces (Economy).
  - **Hardware-backed Key Storage** abstraction (Strongbox/Secure Enclave).
- **Offline Economy**:
  - **Token State**: Offline ledger tracks balances.
  - **Settlement**: Syncs with blockchain when online.
- **Resilience**: Exponential Back-off with Jitter for connection stability.

## Architecture

### 1. Protocol Stack

| Layer | Implementation |
|-------|----------------|
| **App** | Telemetry, File Transfer, Value Transfer |
| **Economy** | `Ledger`, `Transaction` (Offline state) |
| **Protocol** | Deon State Machine (Handshaking, Streaming) |
| **Security** | PAKE (SPAKE2), XChaCha20-Poly1305 |
| **Transport** | `SecureTransport` Trait (BLE / TCP) |

### 2. Economy & Settlement
- **Token State Management**: Local ledgers track "who has how much" while offline.
- **Double-Spend Protection**: Transactions use monotonic nonces and Ed25519 signatures.
- **Settlement Layer**: Abstracted interface (`SettlementLayer`) to commit finalized batches to a blockchain.

### 3. Usage

```rust
use deon_protocol::{DeonProtocol, TcpTransport};
use deon_protocol::economy::{Transaction, Ledger};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Transport & Protocol
    let transport = deon_protocol::transport::connect_tcp("127.0.0.1:8080").await?;
    let mut deon = DeonProtocol::new(transport);
    deon.handshake("123456").await?;
    
    // 2. Offline Economy (Example)
    let ledger = Ledger::new();
    // Logic to sign/verify offline transactions...
    
    Ok(())
}
```

## Changelog

### v1.3.3
- **Fix**: Moved Session Resumption Ticket creation to immediately after shared secret derivation (server-side) to ensure availability during handshake completion.

### v1.3.2
- **Security Upgrade**: Migrated to XChaCha20Poly1305 (24-byte nonce) for superior replay protection.
- **Fix**: Resolved Session ID desynchronization between client/server.
- **New Feature**: Added `economy` module (Token state, Transactions, Settlement abstraction).
- **Docs**: Comprehensive architecture update and contribution guidelines.

## Requirements

- Rust 1.75+
- OpenSSL (optional, depends on platform)

## License

Apache License 2.0
