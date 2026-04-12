pub mod error;
pub mod types;
pub mod crypto;
pub mod transport;
pub mod protocol;
pub mod economy;

pub use error::DeonError;
pub use protocol::DeonProtocol;
pub use transport::{SecureTransport, TransportType, TcpTransport};
pub use crypto::{KeyStorage, FileKeyStorage, SecurityContext};

use std::path::{Path, PathBuf};

/// Send a file with one call: connect, handshake, transfer.
pub async fn send_file<P: AsRef<Path>>(
	file_path: P,
	address: &str,
	pin: &str,
) -> Result<(), DeonError> {
	let mut protocol = DeonProtocol::connect(address, pin).await?;
	protocol.send_file_path(file_path).await
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
