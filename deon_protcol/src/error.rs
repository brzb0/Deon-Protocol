use thiserror::Error;

#[derive(Error, Debug, Clone, Copy)]
#[repr(u8)]
pub enum DeonError {
    #[error("IO Error")]
    Io = 0x01,

    #[error("Serialization Error")]
    Serialization = 0x02,

    #[error("Crypto Error")]
    Crypto = 0x03,

    #[error("Handshake Failed")]
    HandshakeError = 0x04,

    #[error("Protocol Violation")]
    ProtocolViolation = 0x05,

    #[error("Timeout")]
    Timeout = 0x06,

    #[error("Invalid State")]
    InvalidState = 0x07,

    #[error("Authentication Failed")]
    AuthFailed = 0x08,

    #[error("Rate Limited (DoS Protection)")]
    RateLimited = 0x09,

    #[error("Schema Incompatible")]
    SchemaIncompatible = 0x0A,

    #[error("Device Banned")]
    DeviceBanned = 0x0B,

    #[error("Session Expired")]
    SessionExpired = 0x0C,
}

impl From<std::io::Error> for DeonError {
    fn from(_: std::io::Error) -> Self {
        DeonError::Io
    }
}

impl From<postcard::Error> for DeonError {
    fn from(_: postcard::Error) -> Self {
        DeonError::Serialization
    }
}

impl From<spake2::Error> for DeonError {
    fn from(_: spake2::Error) -> Self {
        DeonError::HandshakeError
    }
}
