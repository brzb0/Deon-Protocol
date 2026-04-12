# Deon Protocol v1.3.4

Repository: [https://github.com/brzb0/Deon-Protocol](https://github.com/brzb0/Deon-Protocol)

Deon Protocol is a secure way to move files between devices using a shared password.
It is designed to work fast, keep data private, and stay useful even in unstable networks.

## What You Get

- Simple CLI for sending and receiving files.
- End-to-end encrypted transfer.
- No account, no cloud dependency, no extra server required.
- Rust crate if you want to embed the protocol into your app.

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

The crate also includes lower-level protocol and economy modules for advanced integrations.

## How It Works (Without the Jargon)

1. Sender and receiver agree on a password.
2. They create a secure encrypted session.
3. File is split into chunks and transmitted safely.
4. Receiver writes the file to disk.

## Highlights in 1.3.4

- Simpler public API with one-call helpers.
- Simpler CLI with fewer required flags.
- Better defaults for local usage.
- Documentation cleanup for faster onboarding.

## License

Apache License 2.0
