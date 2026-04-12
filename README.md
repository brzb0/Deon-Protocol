# Deon Protocol v1.3.6

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

Deon Protocol is a secure way to move files between devices using a shared password.
It is designed to work fast, keep data private, and stay useful even in unstable networks.

## What You Get

- Simple CLI for sending and receiving files.
- End-to-end encrypted transfer.
- No account, no cloud dependency, no extra server required.
- Rust crate if you want to embed the protocol into your app.
- Streaming transfer by chunks for large files (videos, datasets, backups).

## Why Use Deon Protocol

- You want secure file transfer without setting up cloud infrastructure.
- You need fast local transfers inside a LAN (office, lab, home network).
- You prefer predictable defaults over complex setup.
- You want to integrate secure transfer into a Rust app with minimal code.
- You need a protocol that still makes sense in unstable or partially offline environments.

## Common Use Cases

- Team file exchange in private networks:
    Move build artifacts, reports, videos, or datasets between machines quickly.

- Industrial or field operations:
    Send logs, sensor captures, or diagnostic bundles from edge devices to operator laptops.

- Local-first product workflows:
    Exchange data between desktop tools and local services without external dependencies.

- Secure handoff for support/QA:
    Ask a user to run one receive command and send encrypted troubleshooting files.

- Embedded/IoT integrations in Rust:
    Use the crate API to embed authenticated, encrypted transfers directly in your service.

## Quick Start (2 Terminals)

Install:

```bash
cargo install deon_protocol
```

Terminal A (receiver):

```bash
deon_protocol receive
```

Terminal B (sender):

```bash
deon_protocol send ./docs.pdf
```

That is it for local testing. By default:

- Address: `127.0.0.1:8080`
- Password: `123456`

For real usage, set your own password:

```bash
set DEON_PASSWORD=my-strong-password
deon_protocol receive --port 8080 --out ./downloads
```

Then from sender machine:

```bash
set DEON_PASSWORD=my-strong-password
deon_protocol send ./docs.pdf 192.168.1.50:8080
```

## CLI Cheatsheet

Receive one file:

```bash
deon_protocol receive
```

Receive on custom port/folder:

```bash
deon_protocol receive --port 9000 --out ./inbox
```

Send with defaults:

```bash
deon_protocol send ./photo.jpg
```

Send to custom address:

```bash
deon_protocol send ./photo.jpg 10.0.0.25:9000
```

Stream send (separate command):

```bash
deon_protocol stream-send ./movie.mp4 10.0.0.25:9000 --content-type video/mp4
```

Stream receive (separate command):

```bash
deon_protocol stream-receive ./capture.bin --port 9000
```

## Streaming Support

Streaming now has its own API and protocol messages, fully separate from file transfer.
This is especially useful for video data, continuous media chunks, or large payloads.

- File transfer API: `send_file(...)` / `receive_file(...)`
- Streaming API: `send_stream(...)`, `send_stream_with_metadata(...)`, `receive_stream(...)`
- CLI file commands: `send`, `receive`
- CLI stream commands: `stream-send`, `stream-receive`

## If You Are a Rust Developer

Add the crate:

```bash
cargo add deon_protocol
```

One-call API (simple mode):

```rust
#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
    deon_protocol::send_file("./docs.pdf", "127.0.0.1:8080", "123456").await?;
    Ok(())
}
```

Streaming API (video/file bytes from any async reader):

```rust
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
    let mut file = tokio::fs::File::open("./movie.mp4").await.map_err(|_| deon_protocol::DeonError::Io)?;
    let size = file.metadata().await.map_err(|_| deon_protocol::DeonError::Io)?.len();

    deon_protocol::send_stream("movie.mp4", size, &mut file, "127.0.0.1:8080", "123456").await?;
    Ok(())
}
```

Stream receive API (to a target file path):

```rust
#[tokio::main]
async fn main() -> Result<(), deon_protocol::DeonError> {
    let receipt = deon_protocol::receive_stream_to_path(8080, "123456", "./incoming.stream").await?;
    println!("{} bytes received from stream {}", receipt.bytes_received, receipt.name);
    Ok(())
}
```

The crate also includes lower-level protocol and economy modules for advanced integrations.

## How It Works (Without the Jargon)

1. Sender and receiver agree on a password.
2. They create a secure encrypted session.
3. File is split into chunks and transmitted safely.
4. Receiver writes the file to disk.

## Highlights in 1.3.6

- Simpler public API with one-call helpers.
- Simpler CLI with fewer required flags.
- Better defaults for local usage.
- Streaming APIs are now fully separated from file transfer APIs.
- Added dedicated stream CLI commands for send/receive.
- Documentation cleanup for faster onboarding.

## License

Apache License 2.0
