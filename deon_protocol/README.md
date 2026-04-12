# Deon Protocol v1.3.6

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

A secure, high-performance file transfer and offline value protocol in Rust.

## Features

- **Secure Authentication**: SPAKE2 (Password-Authenticated Key Exchange) prevents MITM.
- **Strong Encryption**: XChaCha20-Poly1305 with 24-byte random nonces (Replay Protection).
- **Offline Economy**: Built-in support for token state management and offline transactions.
- **Smart Handover**: Auto-switch BLE -> Wi-Fi for large files.
- **Streaming Transfer**: Chunked sender API for large files/video payloads without full in-memory buffering.
- **Separated APIs**: File transfer and stream transfer are handled by different protocol messages and methods.
- **Resilience**: Token bucket rate limiting, exponential backoff, and session resumption.
- **High-Level API**: One-call helpers for send/receive workflows.

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

Receive (defaults: `port=8080`, `out=.`):
```bash
deon_protocol receive
```

Send (defaults: `address=127.0.0.1:8080`):
```bash
deon_protocol send "docs.pdf"
```

Custom receiver output directory:
```bash
deon_protocol receive --port 9000 --out ./downloads --password "123456"
```

Custom sender address:
```bash
deon_protocol send "docs.pdf" "192.168.1.50:9000" --password "123456"
```

Stream send (separate from file transfer command):
```bash
deon_protocol stream-send "movie.mp4" "192.168.1.50:9000" --content-type "video/mp4" --password "123456"
```

Stream receive (separate from file receive command):
```bash
deon_protocol stream-receive "./incoming.stream" --port 9000 --password "123456"
```

Environment password fallback:
```bash
set DEON_PASSWORD=123456
deon_protocol receive
```

### Library (Rust) - High-Level

Send with one call:
```rust
#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
	deon_protocol::send_file("./docs.pdf", "127.0.0.1:8080", "123456").await?;
	Ok(())
}
```

Receive with one call:
```rust
#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
	let saved = deon_protocol::receive_file(8080, "123456", "./downloads").await?;
	println!("Saved file: {}", saved.display());
	Ok(())
}
```

Stream with one call from any async reader:
```rust
#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
	let mut video = tokio::fs::File::open("./movie.mp4").await.map_err(|_| deon_protocol::DeonError::Io)?;
	let size = video.metadata().await.map_err(|_| deon_protocol::DeonError::Io)?.len();

	deon_protocol::send_stream("movie.mp4", size, &mut video, "127.0.0.1:8080", "123456").await?;
	Ok(())
}
```

Stream receive into file path:
```rust
#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
	let receipt = deon_protocol::receive_stream_to_path(8080, "123456", "./incoming.stream").await?;
	println!("stream={} bytes={}", receipt.name, receipt.bytes_received);
	Ok(())
}
```

### Library (Rust) - Lower-Level Control

The original lower-level API remains available for advanced integrations:

```rust
use deon_protocol::DeonProtocol;

#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
	let mut sender = DeonProtocol::connect("127.0.0.1:8080", "123456").await?;
	sender.send_file_path("./docs.pdf").await?;
	Ok(())
}
```

Economy module remains unchanged and can still be used through `economy::{Transaction, Ledger, SettlementLayer}`.

## Changelog

### v1.3.6
- **Protocol**: Added dedicated stream messages (`StreamStart`, `StreamChunk`, `StreamEnd`) separate from file transfer messages.
- **API**: Added `receive_stream_into_writer(...)` and `receive_stream_to_path(...)` on `DeonProtocol`.
- **Root API**: Added `receive_stream(...)` and `receive_stream_to_path(...)` one-call helpers.
- **CLI**: Added dedicated commands `stream-send` and `stream-receive`.

### v1.3.5
- **Streaming**: Added `DeonProtocol::send_stream(...)` for chunked transfer from any `AsyncRead` source.
- **Memory**: Updated `DeonProtocol::send_file_path(...)` to stream from disk instead of loading full file bytes.
- **API**: Added root helper `send_stream(...)` for one-call streaming workflows.

### v1.3.4
- **API**: Added high-level one-call helpers: `send_file(...)` and `receive_file(...)`.
- **Protocol API**: Added convenience methods `DeonProtocol::connect`, `listen`, `send_file_path`, `receive_file_into`.
- **CLI**: Simplified commands with positional arguments and useful defaults.
- **Docs**: Updated usage examples and onboarding flow.

### v1.3.3
- **Fix**: Moved Session Resumption Ticket creation to immediately after shared secret derivation (server-side).

### v1.3.2
- **Security**: Replaced ChaCha20Poly1305 with XChaCha20Poly1305 (24-byte nonce) to eliminate nonce reuse risks.
- **Protocol**: Fixed Session ID desynchronization; implemented deterministic session ID derivation.
- **Economy**: Added `economy` module with `Transaction`, `Ledger`, and `SettlementLayer` structures.
- **Docs**: Added CONTRIBUTING.md and improved architecture documentation.

### v1.3.1
- Initial release with SPAKE2 and basic file transfer.
