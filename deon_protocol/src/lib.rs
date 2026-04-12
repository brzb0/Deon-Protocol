pub mod error;
pub mod types;
pub mod crypto;
pub mod transport;
pub mod protocol;
pub mod economy;

pub use error::DeonError;
pub use protocol::{DeonProtocol, StreamReceipt};
pub use transport::{SecureTransport, TransportType, TcpTransport};
pub use crypto::{KeyStorage, FileKeyStorage, SecurityContext};

use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

/// Send a file with one call: connect, handshake, transfer.
pub async fn send_file<P: AsRef<Path>>(
	file_path: P,
	address: &str,
	pin: &str,
) -> Result<(), DeonError> {
	let mut protocol = DeonProtocol::connect(address, pin).await?;
	protocol.send_file_path(file_path).await
}

/// Stream bytes with one call: connect, handshake, transfer.
pub async fn send_stream<R>(
	name: &str,
	total_size: u64,
	reader: &mut R,
	address: &str,
	pin: &str,
) -> Result<(), DeonError>
where
	R: AsyncRead + Unpin,
{
	let mut protocol = DeonProtocol::connect(address, pin).await?;
	protocol.send_stream(name, total_size, reader).await
}

/// Stream bytes with metadata in one call: connect, handshake, transfer.
pub async fn send_stream_with_metadata<R>(
	name: &str,
	total_size: Option<u64>,
	content_type: Option<&str>,
	reader: &mut R,
	address: &str,
	pin: &str,
) -> Result<u64, DeonError>
where
	R: AsyncRead + Unpin,
{
	let mut protocol = DeonProtocol::connect(address, pin).await?;
	protocol
		.send_stream_with_metadata(name, total_size, content_type, reader)
		.await
}

/// Receive one file with one call: listen, handshake, save.
pub async fn receive_file<P: AsRef<Path>>(
	port: u16,
	pin: &str,
	output_dir: P,
) -> Result<PathBuf, DeonError> {
	let mut protocol = DeonProtocol::listen(port, pin).await?;
	protocol.receive_file_into(output_dir).await
}

/// Receive a stream in one call: listen, handshake, write into an AsyncWrite sink.
pub async fn receive_stream<W>(
	port: u16,
	pin: &str,
	writer: &mut W,
) -> Result<StreamReceipt, DeonError>
where
	W: AsyncWrite + Unpin,
{
	let mut protocol = DeonProtocol::listen(port, pin).await?;
	protocol.receive_stream_into_writer(writer).await
}

/// Receive a stream in one call and write to a target file path.
pub async fn receive_stream_to_path<P: AsRef<Path>>(
	port: u16,
	pin: &str,
	output_path: P,
) -> Result<StreamReceipt, DeonError> {
	let mut protocol = DeonProtocol::listen(port, pin).await?;
	protocol.receive_stream_to_path(output_path).await
}
