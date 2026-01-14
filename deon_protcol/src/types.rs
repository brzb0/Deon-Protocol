use serde::{Deserialize, Serialize};

pub const MAGIC_BYTES: u16 = 0xDE01;
pub const VERSION: u8 = 1;

pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_HANDSHAKE: u8 = 0x02;
pub const FLAG_FILE_CHUNK: u8 = 0x04;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 2 + 1 + 1 + NONCE_LEN; // 16 bytes

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProtocolMessage {
    Hello {
        public_key: [u8; 32],
        device_id: String,
    },
    HelloAck {
        public_key: [u8; 32],
    },
    SwitchToWifi {
        ssid: String,
        ip: String,
        port: u16,
    },
    FileHeader {
        filename: String,
        size: u64,
        checksum: u32,
    },
    FileChunk {
        offset: u64,
        data: Vec<u8>,
    },
    Ack {
        id: u64,
    },
    Ping,
    Pong,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub nonce: [u8; NONCE_LEN],
}

impl WireHeader {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..2].copy_from_slice(&self.magic.to_be_bytes());
        buf[2] = self.version;
        buf[3] = self.flags;
        buf[4..16].copy_from_slice(&self.nonce);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        let version = buf[2];
        let flags = buf[3];
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[4..16]);

        if magic != MAGIC_BYTES {
            return None;
        }

        Some(Self {
            magic,
            version,
            flags,
            nonce,
        })
    }
}
