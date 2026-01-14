use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeonError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    Serialization(String),

    #[error("Crypto Error: {0}")]
    Crypto(String),

    #[error("Handshake Failed: {0}")]
    HandshakeError(String),

    #[error("Protocol Violation: {0}")]
    ProtocolViolation(String),

    #[error("Timeout")]
    Timeout,

    #[error("Invalid State: {0}")]
    InvalidState(String),
}

impl From<postcard::Error> for DeonError {
    fn from(e: postcard::Error) -> Self {
        DeonError::Serialization(e.to_string())
    }
}
