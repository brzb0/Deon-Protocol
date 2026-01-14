# Deon Protocol v1.3.0

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

A secure, high-performance file transfer protocol implementation in Rust, featuring SPAKE2 authentication, ChaCha20-Poly1305 encryption, and intelligent Wi-Fi handover.

## Features

- **Secure Authentication**: Uses SPAKE2 (Password-Authenticated Key Exchange) to prevent MITM attacks.
- **Strong Encryption**: All data is encrypted using ChaCha20-Poly1305 with epoch-based nonces.
- **Smart Handover**: Automatically switches from BLE (simulated) to Wi-Fi for files larger than 64KB.
- **Resilience**: Implements token bucket rate limiting and exponential backoff for network reliability.
- **Efficiency**: 64KB chunking for optimal throughput.

## Installation

Ensure you have Rust installed.

```bash
git clone https://github.com/brzb0/Deon-Protocol
cd deon-protocol/deon_protcol
cargo build --release
```

## Usage

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

## License

Apache License 2.0
