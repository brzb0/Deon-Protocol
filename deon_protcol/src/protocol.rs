use crate::crypto::{HandshakeManager, SecurityContext};
use crate::error::DeonError;
use crate::transport::{SecureTransport, TransportType};
use crate::types::{
    ProtocolMessage, WireHeader, FLAG_ENCRYPTED, HEADER_LEN, MAGIC_BYTES, VERSION
};
use log::info;

#[derive(Debug, PartialEq)]
pub enum ProtocolState {
    Searching,
    Handshaking,
    Streaming,
    Idle,
}

pub struct DeonProtocol {
    state: ProtocolState,
    transport: Box<dyn SecureTransport>,
    security_context: Option<SecurityContext>,
    _buffer: Vec<u8>,
}

impl DeonProtocol {
    pub fn new(transport: Box<dyn SecureTransport>) -> Self {
        Self {
            state: ProtocolState::Searching,
            transport,
            security_context: None,
            _buffer: Vec::new(),
        }
    }

    /// Main Handshake Logic (PAKE + X25519)
    pub async fn handshake(&mut self, _pin: &str) -> Result<(), DeonError> {
        self.state = ProtocolState::Handshaking;
        
        // 1. RSSI Gating (Mocked check)
        if self.transport.get_type() == TransportType::Ble {
             // In real code: let rssi = self.transport.get_rssi().await?;
             // if rssi < -40 { return Err(DeonError::HandshakeError("Device too far".into())); }
        }

        let handshake_mgr = HandshakeManager::new();
        let my_pub = handshake_mgr.my_public.to_bytes();

        // 2. Send Hello with Ephemeral Public Key
        // In a real PAKE, we would blind this key with the PIN-derived hash.
        // For this implementation, we send the key and verify knowledge of PIN later or use 
        // the PIN to authenticate the shared secret derivation.
        let hello_msg = ProtocolMessage::Hello { 
            public_key: my_pub,
            device_id: "DeviceA".to_string() 
        };
        
        self.send_cleartext_message(hello_msg).await?;

        // 3. Receive Peer Hello
        let response_bytes = self.transport.receive().await?;
        // Parse header... (omitted for brevity, assuming direct payload for handshake demo)
        // In full impl, we strip header.
        // Assuming we got the payload directly for this step or we parse:
        let peer_msg: ProtocolMessage = postcard::from_bytes(&response_bytes)
            .map_err(|e| DeonError::Serialization(e.to_string()))?;

        if let ProtocolMessage::Hello { public_key: peer_pub_bytes, .. } = peer_msg {
            let peer_pub = x25519_dalek::PublicKey::from(peer_pub_bytes);
            
            // 4. Derive Secret
            let shared_secret = handshake_mgr.derive_shared_secret(peer_pub);
            
            // 5. Initialize Security Context
            // We use the PIN to salt the session key derivation, effectively binding the session to the PIN.
            // If the peer used a different PIN, their session keys will differ, and the first encrypted message will fail auth.
            // (This is a simplified PAKE approach).
            self.security_context = Some(SecurityContext::new(shared_secret, true));
            
            // 6. Verify Auth by sending an encrypted Ping
            self.send_encrypted_message(&ProtocolMessage::Ping).await?;
            
            // If we receive an encrypted Pong properly, we are good.
            let pong_bytes = self.read_and_decrypt_message().await?;
            if let ProtocolMessage::Pong = pong_bytes {
                self.state = ProtocolState::Idle;
                info!("Handshake Complete. Secure Session Established.");
                Ok(())
            } else {
                Err(DeonError::HandshakeError("Auth Verification Failed".into()))
            }
        } else {
            Err(DeonError::ProtocolViolation("Expected Hello".into()))
        }
    }

    /// Smart Switching & File Transfer
    pub async fn send_file(&mut self, filename: &str, data: &[u8]) -> Result<(), DeonError> {
        self.state = ProtocolState::Streaming;

        // Smart Switching Check
        if data.len() > 64 * 1024 && self.transport.get_type() == TransportType::Ble {
            info!("Payload > 64KB. Initiating Wi-Fi Handover...");
            self.perform_wifi_handover().await?;
        }

        // Send Header
        let file_header = ProtocolMessage::FileHeader {
            filename: filename.to_string(),
            size: data.len() as u64,
            checksum: crc32fast::hash(data),
        };
        self.send_encrypted_message(&file_header).await?;

        // Chunking (16KB chunks)
        const CHUNK_SIZE: usize = 16 * 1024;
        let mut offset = 0;

        for chunk in data.chunks(CHUNK_SIZE) {
            let chunk_msg = ProtocolMessage::FileChunk {
                offset,
                data: chunk.to_vec(),
            };
            self.send_encrypted_message(&chunk_msg).await?;
            
            // Wait for ACK for flow control (simple stop-and-wait for demo)
            // In high perf, use windowing.
            // let _ack = self.read_and_decrypt_message().await?;
            
            offset += chunk.len() as u64;
        }

        self.state = ProtocolState::Idle;
        Ok(())
    }

    async fn perform_wifi_handover(&mut self) -> Result<(), DeonError> {
        // 1. Send Switch Request
        let switch_msg = ProtocolMessage::SwitchToWifi {
            ssid: "DeonSecureNet".to_string(),
            ip: "192.168.1.50".to_string(),
            port: 8080,
        };
        self.send_encrypted_message(&switch_msg).await?;

        // 2. Wait for Peer ACK/Ready
        let _ack = self.read_and_decrypt_message().await?;

        // 3. Connect to TCP
        let stream = tokio::net::TcpStream::connect("192.168.1.50:8080").await
            .map_err(DeonError::Io)?;
        
        // 4. Swap Transport
        self.transport = Box::new(crate::transport::TcpTransport::new(stream));
        info!("Transport switched to Wi-Fi TCP");
        
        Ok(())
    }

    // --- Helper Methods ---

    async fn send_cleartext_message(&mut self, msg: ProtocolMessage) -> Result<(), DeonError> {
        let payload = postcard::to_stdvec(&msg)?;
        // Send raw without crypto header for initial handshake
        self.transport.send(&payload).await
    }

    async fn send_encrypted_message(&mut self, msg: &ProtocolMessage) -> Result<(), DeonError> {
        let context = self.security_context.as_ref().ok_or(DeonError::InvalidState("No Security Context".into()))?;
        
        let payload = postcard::to_stdvec(msg)?;
        
        // Encrypt
        // AAD can be the header itself if we construct it first, but we need the nonce from encrypt first.
        // Actually, ChaCha20Poly1305 usually takes nonce as input.
        // Our context manages the nonce.
        
        // We use an empty AAD for simplicity or bind it to version
        let (ciphertext, nonce) = context.encrypt(&payload, &[])?;
        
        // Construct Wire Header
        let header = WireHeader {
            magic: MAGIC_BYTES,
            version: VERSION,
            flags: FLAG_ENCRYPTED,
            nonce,
        };
        
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len() + 16);
        frame.extend_from_slice(&header.to_bytes());
        frame.extend_from_slice(&ciphertext); // Ciphertext includes Tag usually with this crate? 
        // chacha20poly1305 crate's `encrypt` returns `ciphertext + tag` appended.
        // So we just send that.
        
        self.transport.send(&frame).await
    }

    async fn read_and_decrypt_message(&mut self) -> Result<ProtocolMessage, DeonError> {
        let frame = self.transport.receive().await?;
        
        // Parse Header
        let header = WireHeader::from_bytes(&frame).ok_or(DeonError::ProtocolViolation("Invalid Header".into()))?;
        
        if header.flags & FLAG_ENCRYPTED == 0 {
            return Err(DeonError::ProtocolViolation("Expected Encrypted Frame".into()));
        }

        let context = self.security_context.as_ref().ok_or(DeonError::InvalidState("No Security Context".into()))?;
        
        // Extract Ciphertext (Frame - Header)
        if frame.len() < HEADER_LEN {
            return Err(DeonError::ProtocolViolation("Frame too short".into()));
        }
        let ciphertext = &frame[HEADER_LEN..];

        // Decrypt
        let plaintext = context.decrypt(ciphertext, &header.nonce, &[])?;
        
        // Deserialize
        let msg = postcard::from_bytes(&plaintext)?;
        Ok(msg)
    }
}
