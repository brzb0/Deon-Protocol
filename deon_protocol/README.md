# Deon Protocol v1.3.2

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

A secure, high-performance file transfer and offline value protocol in Rust.

## Features

- **Secure Authentication**: SPAKE2 (Password-Authenticated Key Exchange) prevents MITM.
- **Strong Encryption**: XChaCha20-Poly1305 with 24-byte random nonces (Replay Protection).
- **Offline Economy**: Built-in support for token state management and offline transactions.
- **Smart Handover**: Auto-switch BLE -> Wi-Fi for large files.
- **Resilience**: Token bucket rate limiting, exponential backoff, and session resumption.

## Architecture

### 1. Token State Management (Offline)
Deon maintains an offline ledger (`economy::Ledger`) to track "Who has how much". Transactions are signed (Ed25519) and verified locally without internet access.

### 2. Replay & Double-Spend Protection
- **Transport Layer**: XChaCha20-Poly1305 uses 24-byte random nonces to prevent replay of encrypted frames.
- **Economic Layer**: Transactions include a monotonic `nonce` checked against the local ledger state to prevent double-spending.

### 3. Settlement Layer
When connectivity is restored, the `SettlementLayer` trait facilitates syncing offline transactions to a blockchain (e.g., Solana, Ethereum) for final validation.

## Installation

From Crates.io:
```bash
cargo install deon_protocol
```

Add as dependency:
```bash
cargo add deon_protocol
```

Or build from source:
```bash
git clone https://github.com/brzb0/Deon-Protocol
cd Deon-Protocol/deon_protocol
cargo build --release
```

## Usage

### CLI

**Receive Mode:**
```bash
deon_protocol receive --port 8080 --password "123456"
```

**Send Mode:**
```bash
deon_protocol send --file "docs.pdf" --address "127.0.0.1:8080" --password "123456"
```

### Library (Rust)

```rust
use deon_protocol::economy::{Transaction, Ledger};

// Offline Transaction
let mut ledger = Ledger::new();
// ... process transactions ...
```

## Changelog

### v1.3.2
- **Security**: Replaced ChaCha20Poly1305 with XChaCha20Poly1305 (24-byte nonce) to eliminate nonce reuse risks.
- **Protocol**: Fixed Session ID desynchronization; implemented deterministic session ID derivation.
- **Economy**: Added `economy` module with `Transaction`, `Ledger`, and `SettlementLayer` structures.
- **Docs**: Added CONTRIBUTING.md and improved architecture documentation.

### v1.3.1
- Initial release with SPAKE2 and basic file transfer.
