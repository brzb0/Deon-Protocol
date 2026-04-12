use crate::crypto::{SecurityContext, ResumptionTicket};
use crate::error::DeonError;
use crate::transport::{SecureTransport, TransportType};
use crate::types::{
    ProtocolMessage, WireHeader, FLAG_ENCRYPTED, HEADER_LEN, MAGIC_BYTES, VERSION
};
use log::{info, debug};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

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
    resumption_ticket: Option<ResumptionTicket>,
    _buffer: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StreamReceipt {
    pub name: String,
    pub content_type: Option<String>,
    pub expected_size: Option<u64>,
    pub bytes_received: u64,
}

impl DeonProtocol {
    pub fn new(transport: Box<dyn SecureTransport>) -> Self {
        Self {
            state: ProtocolState::Searching,
            transport,
            security_context: None,
            resumption_ticket: None,
            _buffer: Vec::new(),
        }
    }

    /// Connect to a TCP peer and complete handshake in one call.
    pub async fn connect(address: &str, pin: &str) -> Result<Self, DeonError> {
        let transport = crate::transport::connect_tcp(address).await?;
        let mut protocol = Self::new(transport);
        protocol.handshake(pin).await?;
        Ok(protocol)
    }

    /// Listen on a TCP port, accept one peer and complete handshake in one call.
    pub async fn listen(port: u16, pin: &str) -> Result<Self, DeonError> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        let (socket, _) = listener.accept().await?;

        let transport = Box::new(crate::transport::TcpTransport::new(socket));
        let mut protocol = Self::new(transport);
        protocol.accept_handshake(pin).await?;
        Ok(protocol)
    }

    /// Read a local file path and send it as a secure transfer.
    pub async fn send_file_path<P: AsRef<Path>>(&mut self, file_path: P) -> Result<(), DeonError> {
        let path = file_path.as_ref();
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(DeonError::ProtocolViolation)?;

        let mut file = tokio::fs::File::open(path).await?;
        let total_size = file.metadata().await?.len();
        self.send_file_from_reader(filename, total_size, &mut file).await
    }

    /// Send a file payload from any AsyncRead source using file-transfer messages.
    pub async fn send_file_from_reader<R>(&mut self, filename: &str, total_size: u64, reader: &mut R) -> Result<(), DeonError>
    where
        R: AsyncRead + Unpin,
    {
        self.state = ProtocolState::Streaming;

        if total_size > 64 * 1024 && self.transport.get_type() == TransportType::Ble {
            info!("Payload > 64KB. Initiating Wi-Fi Handover...");
            self.perform_wifi_handover().await?;
        }

        let file_header = ProtocolMessage::FileHeader {
            filename: filename.to_string(),
            size: total_size,
            checksum: 0,
        };
        self.send_encrypted_message(&file_header).await?;

        const CHUNK_SIZE: usize = 64 * 1024;
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut offset = 0u64;

        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }

            let chunk_msg = ProtocolMessage::FileChunk {
                offset,
                data: buffer[..read].to_vec(),
            };

            self.send_encrypted_message(&chunk_msg).await?;
            offset += read as u64;

            if offset > total_size {
                self.state = ProtocolState::Idle;
                return Err(DeonError::ProtocolViolation);
            }
        }

        if offset != total_size {
            self.state = ProtocolState::Idle;
            return Err(DeonError::ProtocolViolation);
        }

        self.state = ProtocolState::Idle;
        Ok(())
    }

    /// --- 1. SPAKE2 Handshake ---
    /// Implements password-authenticated key exchange to prevent MITM and verify PIN.
    pub async fn handshake(&mut self, pin: &str) -> Result<(), DeonError> {
        debug!("Starting Handshake with PIN: {}", pin);
        self.state = ProtocolState::Handshaking;
        
        // 1. RSSI Gating
        if self.transport.get_type() == TransportType::Ble {
            let rssi = self.transport.get_rssi().await?;
            debug!("RSSI: {}", rssi);
            // Requirement: RSSI must be >= -45dBm
            if rssi < -45 {
                 info!("Handshake rejected due to low RSSI: {}", rssi);
                 return Err(DeonError::HandshakeError);
            }
        }

        // 2. Check for Session Resumption (Optimization)
        if let Some(ticket) = self.resumption_ticket.clone() {
             // Validate ticket expiry
             let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
             if ticket.expiry == 0 || ticket.expiry > now {
                 debug!("Attempting Session Resumption...");
                 let resume_msg = ProtocolMessage::Resume { 
                     session_id: ticket.session_id 
                 };
                 // We need to send it.
                 if let Ok(_) = self.send_cleartext_message(resume_msg).await {
                     // Wait for Ack
                     if let Ok(response_bytes) = self.transport.receive().await {
                         if let Ok(response) = postcard::from_bytes::<ProtocolMessage>(&response_bytes) {
                             if let ProtocolMessage::ResumeAck = response {
                                 info!("Session Resumed Successfully!");
                                 self.security_context = Some(SecurityContext::new(ticket.key, true));
                                 self.state = ProtocolState::Idle;
                                 return Ok(());
                             }
                         }
                     }
                 }
                 debug!("Resumption failed, falling back to full handshake.");
             }
        }

        debug!("Initializing SPAKE2...");
        // 3. SPAKE2 Init
        let pwd = Password::new(pin.as_bytes());
        let id_a = Identity::new(b"device_a");
        let id_b = Identity::new(b"device_b");

        let (s1, msg1) = Spake2::<Ed25519Group>::start_a(
            &pwd,
            &id_a, 
            &id_b
        );

        // 4. Send Message 1
        let hello_msg = ProtocolMessage::Hello { 
            public_key: msg1, // Reusing public_key field for SPAKE msg1
            device_id: "DeviceA".to_string() 
        };
        debug!("Sending Client Hello...");
        self.send_cleartext_message(hello_msg).await?;

        // 5. Receive Message 2
        debug!("Waiting for Server Hello...");
        let response_bytes = self.transport.receive().await?;
        debug!("Received {} bytes", response_bytes.len());
        let peer_msg: ProtocolMessage = postcard::from_bytes(&response_bytes)?;

        if let ProtocolMessage::Hello { public_key: msg2_bytes, .. } = peer_msg {
             debug!("Got Server Hello. Finishing SPAKE2...");
             // 6. Finish SPAKE2
             let key = s1.finish(&msg2_bytes)
                .map_err(|e| {
                    info!("SPAKE2 Finish failed: {:?}", e);
                    DeonError::HandshakeError
                })?;
             
             debug!("SPAKE2 Handshake Success! Shared Key Derived.");
             // Key is the shared secret!
             let mut shared_secret = [0u8; 32];
             shared_secret.copy_from_slice(&key[0..32]);

             // 7. Init Security Context
             self.security_context = Some(SecurityContext::new(shared_secret, true));
             
             // 8. Verify Auth (Ping/Pong)
             self.send_encrypted_message(&ProtocolMessage::Ping).await?;
             let pong_msg = self.read_and_decrypt_message().await?;
             
             if let ProtocolMessage::Pong = pong_msg {
                 self.state = ProtocolState::Idle;
                 
                 // Issue/Store Resumption Ticket
                 // Derive deterministic Session ID from Shared Secret
                 let mut session_id = [0u8; 32];
                 let hk = Hkdf::<Sha256>::new(None, &shared_secret);
                 hk.expand(b"deon_session_id", &mut session_id).unwrap();

                 self.resumption_ticket = Some(ResumptionTicket {
                     session_id,
                     key: shared_secret,
                     expiry: 0, // Infinite for demo
                 });
                 
                 info!("SPAKE2 Handshake Complete. Secure Session Established.");
                 Ok(())
             } else {
                 Err(DeonError::HandshakeError)
             }
        } else {
            Err(DeonError::ProtocolViolation)
        }
    }

    /// --- 1.1 SPAKE2 Handshake (Responder/Server) ---
    /// Accepts a handshake from a client.
    pub async fn accept_handshake(&mut self, pin: &str) -> Result<(), DeonError> {
        debug!("Waiting for Handshake from Client (PIN: {})", pin);
        self.state = ProtocolState::Handshaking;

        // 1. Receive Client Hello (SPAKE2 Msg1)
        let msg_bytes = self.transport.receive().await?;
        let msg: ProtocolMessage = postcard::from_bytes(&msg_bytes)?;

        match msg {
            ProtocolMessage::Resume { session_id } => {
                debug!("Received Resume Request");
                if let Some(ticket) = self.resumption_ticket.clone() {
                    if ticket.session_id == session_id {
                        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                        if ticket.expiry == 0 || ticket.expiry > now {
                            debug!("Session ID matched. Resuming...");
                            self.send_cleartext_message(ProtocolMessage::ResumeAck).await?;
                            self.security_context = Some(SecurityContext::new(ticket.key, false));
                            self.state = ProtocolState::Idle;
                            info!("Session Resumed (Responder).");
                            return Ok(());
                        }
                    }
                }
                debug!("Resumption failed. Rejecting.");
                return Err(DeonError::HandshakeError);
            }
            ProtocolMessage::Hello { public_key: msg1_bytes, .. } => {
                debug!("Received Client Hello. Starting SPAKE2 Responder...");

                // 2. SPAKE2 Responder Init
                let pwd = Password::new(pin.as_bytes());
                let id_a = Identity::new(b"device_a");
                let id_b = Identity::new(b"device_b");

                let (s2, msg2) = Spake2::<Ed25519Group>::start_b(
                    &pwd,
                    &id_a, 
                    &id_b
                );

                // 3. Derive Key
                let key = s2.finish(&msg1_bytes)
                    .map_err(|e| {
                        info!("SPAKE2 Finish failed: {:?}", e);
                        DeonError::HandshakeError
                    })?;
                
                let mut shared_secret = [0u8; 32];
                shared_secret.copy_from_slice(&key[0..32]);

                // Issue Ticket immediately after key derivation
                // Derive deterministic Session ID from Shared Secret
                let mut session_id = [0u8; 32];
                let hk = Hkdf::<Sha256>::new(None, &shared_secret);
                hk.expand(b"deon_session_id", &mut session_id).unwrap();

                self.resumption_ticket = Some(ResumptionTicket {
                    session_id,
                    key: shared_secret,
                    expiry: 0,
                });

                // 4. Send Server Hello (SPAKE2 Msg2)
                let response = ProtocolMessage::Hello {
                    public_key: msg2,
                    device_id: "DeviceB".to_string(),
                };
                self.send_cleartext_message(response).await?;

                // 5. Init Security Context (Responder)
                self.security_context = Some(SecurityContext::new(shared_secret, false));
                debug!("SPAKE2 Shared Key Derived.");

                // 6. Wait for Ping (Verify Auth)
                let ping_msg = self.read_and_decrypt_message().await?;
                if let ProtocolMessage::Ping = ping_msg {
                    debug!("Received Ping. Sending Pong...");
                    self.send_encrypted_message(&ProtocolMessage::Pong).await?;
                    
                    self.state = ProtocolState::Idle;
                    info!("Secure Session Established (Responder).");
                    Ok(())
                } else {
                    Err(DeonError::HandshakeError)
                }
            }
            _ => Err(DeonError::ProtocolViolation),
        }
    }

    /// --- 2. Secure File Transfer (Receive) ---
    pub async fn receive_file(&mut self) -> Result<(), DeonError> {
        self.receive_file_into(".").await.map(|_| ())
    }

    /// Receive one file and store it in the given output directory.
    pub async fn receive_file_into<P: AsRef<Path>>(&mut self, output_dir: P) -> Result<PathBuf, DeonError> {
        self.state = ProtocolState::Streaming;
        let output_dir = output_dir.as_ref();
        tokio::fs::create_dir_all(output_dir).await?;

        let mut file: Option<tokio::fs::File> = None;
        let mut expected_size = 0u64;
        let mut received_size = 0u64;
        let mut saved_path: Option<PathBuf> = None;

        loop {
            let msg = self.read_and_decrypt_message().await?;

            match msg {
                ProtocolMessage::FileHeader { filename, size, .. } => {
                    let safe_filename = Path::new(&filename)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .filter(|name| !name.is_empty())
                        .ok_or(DeonError::ProtocolViolation)?;

                    let target_path = output_dir.join(safe_filename);
                    info!("Receiving File: {} ({} bytes)", target_path.display(), size);

                    expected_size = size;
                    received_size = 0;

                    file = Some(tokio::fs::File::create(&target_path).await?);
                    saved_path = Some(target_path);

                    if expected_size == 0 {
                        self.state = ProtocolState::Idle;
                        return saved_path.ok_or(DeonError::InvalidState);
                    }
                }
                ProtocolMessage::FileChunk { offset, data } => {
                    if let Some(f) = file.as_mut() {
                         use tokio::io::{AsyncSeekExt, AsyncWriteExt};

                         f.seek(tokio::io::SeekFrom::Start(offset)).await.map_err(|_| DeonError::Io)?;
                         f.write_all(&data).await.map_err(|_| DeonError::Io)?;
                         
                         received_size += data.len() as u64;
                         
                         // Log progress every 1MB or so
                         if received_size % (1024 * 1024) == 0 || received_size == expected_size {
                             info!("Progress: {}/{} bytes", received_size, expected_size);
                         }

                         if received_size >= expected_size {
                             self.state = ProtocolState::Idle;
                             let path = saved_path.ok_or(DeonError::InvalidState)?;
                             info!("File Transfer Complete: {}", path.display());
                             return Ok(path);
                         }
                    } else {
                        return Err(DeonError::ProtocolViolation);
                    }
                }
                _ => {
                    debug!("Received other message: {:?}", msg);
                }
            }
        }
    }

    /// --- 2. Secure File Transfer with Chunking ---
    pub async fn send_file(&mut self, filename: &str, data: &[u8]) -> Result<(), DeonError> {
        self.state = ProtocolState::Streaming;

        // Smart Switching Check (Requirement: > 64KB -> Wi-Fi)
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
        
        // Retry Strategy is handled inside send_encrypted_message
        self.send_encrypted_message(&file_header).await?;

        // Chunking (64KB chunks as requested)
        const CHUNK_SIZE: usize = 64 * 1024;
        let mut offset = 0;
        let mut chunk_hasher = crc32fast::Hasher::new();

        for chunk in data.chunks(CHUNK_SIZE) {
            chunk_hasher.update(chunk);
            let _chunk_checksum = chunk_hasher.clone().finalize();
            
            let chunk_msg = ProtocolMessage::FileChunk {
                offset,
                data: chunk.to_vec(),
            };
            
            self.send_encrypted_message(&chunk_msg).await?;
            
            // Wait for ACK (Stop-and-Wait)
            // In high performance scenario, we'd use sliding window.
            // For now, assume implicit ACK or transport reliability if TCP.
            // On BLE, we should wait for app-level ACK.
            if self.transport.get_type() == TransportType::Ble {
                 // let _ack = self.read_and_decrypt_message().await?;
            }
            
            offset += chunk.len() as u64;
            
            // DoS Protection: Token Bucket check is inside encrypt()
        }

        self.state = ProtocolState::Idle;
        Ok(())
    }

    /// Stream binary data from any AsyncRead source.
    ///
    /// This is intended for large payloads (e.g., videos) where loading everything
    /// into memory is not desirable.
    pub async fn send_stream<R>(&mut self, name: &str, total_size: u64, reader: &mut R) -> Result<(), DeonError>
    where
        R: AsyncRead + Unpin,
    {
        self.send_stream_with_metadata(name, Some(total_size), None, reader)
            .await
            .map(|_| ())
    }

    /// Stream data from any AsyncRead source using dedicated streaming messages.
    pub async fn send_stream_with_metadata<R>(
        &mut self,
        name: &str,
        total_size: Option<u64>,
        content_type: Option<&str>,
        reader: &mut R,
    ) -> Result<u64, DeonError>
    where
        R: AsyncRead + Unpin,
    {
        self.state = ProtocolState::Streaming;

        if total_size.unwrap_or(0) > 64 * 1024 && self.transport.get_type() == TransportType::Ble {
            info!("Payload > 64KB. Initiating Wi-Fi Handover...");
            self.perform_wifi_handover().await?;
        }

        let stream_start = ProtocolMessage::StreamStart {
            name: name.to_string(),
            total_size,
            content_type: content_type.map(|value| value.to_string()),
        };
        self.send_encrypted_message(&stream_start).await?;

        const CHUNK_SIZE: usize = 64 * 1024;
        let mut sequence = 0u64;
        let mut total_sent = 0u64;
        let mut buffer = vec![0u8; CHUNK_SIZE];

        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }

            let chunk = ProtocolMessage::StreamChunk {
                sequence,
                data: buffer[..read].to_vec(),
            };
            self.send_encrypted_message(&chunk).await?;

            sequence += 1;
            total_sent += read as u64;

            if let Some(expected) = total_size {
                if total_sent > expected {
                    self.state = ProtocolState::Idle;
                    return Err(DeonError::ProtocolViolation);
                }
            }
        }

        if let Some(expected) = total_size {
            if total_sent != expected {
                self.state = ProtocolState::Idle;
                return Err(DeonError::ProtocolViolation);
            }
        }

        let end = ProtocolMessage::StreamEnd {
            total_bytes: total_sent,
        };
        self.send_encrypted_message(&end).await?;

        self.state = ProtocolState::Idle;
        Ok(total_sent)
    }

    /// Receive stream payload into any AsyncWrite sink.
    pub async fn receive_stream_into_writer<W>(&mut self, writer: &mut W) -> Result<StreamReceipt, DeonError>
    where
        W: AsyncWrite + Unpin,
    {
        self.state = ProtocolState::Streaming;

        let first = self.read_and_decrypt_message().await?;
        let (name, expected_size, content_type) = match first {
            ProtocolMessage::StreamStart {
                name,
                total_size,
                content_type,
            } => (name, total_size, content_type),
            _ => {
                self.state = ProtocolState::Idle;
                return Err(DeonError::ProtocolViolation);
            }
        };

        let mut expected_sequence = 0u64;
        let mut bytes_received = 0u64;

        loop {
            match self.read_and_decrypt_message().await? {
                ProtocolMessage::StreamChunk { sequence, data } => {
                    if sequence != expected_sequence {
                        self.state = ProtocolState::Idle;
                        return Err(DeonError::ProtocolViolation);
                    }

                    writer.write_all(&data).await?;
                    bytes_received += data.len() as u64;
                    expected_sequence += 1;

                    if let Some(expected) = expected_size {
                        if bytes_received > expected {
                            self.state = ProtocolState::Idle;
                            return Err(DeonError::ProtocolViolation);
                        }

                        if bytes_received % (1024 * 1024) == 0 || bytes_received == expected {
                            info!("Stream progress: {}/{} bytes", bytes_received, expected);
                        }
                    } else if bytes_received % (1024 * 1024) == 0 {
                        info!("Stream progress: {} bytes", bytes_received);
                    }
                }
                ProtocolMessage::StreamEnd { total_bytes } => {
                    if total_bytes != bytes_received {
                        self.state = ProtocolState::Idle;
                        return Err(DeonError::ProtocolViolation);
                    }

                    if let Some(expected) = expected_size {
                        if expected != bytes_received {
                            self.state = ProtocolState::Idle;
                            return Err(DeonError::ProtocolViolation);
                        }
                    }

                    writer.flush().await?;
                    self.state = ProtocolState::Idle;

                    return Ok(StreamReceipt {
                        name,
                        content_type,
                        expected_size,
                        bytes_received,
                    });
                }
                _ => {
                    self.state = ProtocolState::Idle;
                    return Err(DeonError::ProtocolViolation);
                }
            }
        }
    }

    /// Receive a stream and persist it into a single file path.
    pub async fn receive_stream_to_path<P: AsRef<Path>>(&mut self, output_path: P) -> Result<StreamReceipt, DeonError> {
        let path = output_path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let mut file = tokio::fs::File::create(path).await?;
        self.receive_stream_into_writer(&mut file).await
    }

    async fn perform_wifi_handover(&mut self) -> Result<(), DeonError> {
        // 1. Send Switch Request
        let switch_msg = ProtocolMessage::SwitchToWifi {
            ssid: "DeonSecureNet".to_string(),
            ip: "192.168.1.50".to_string(),
            port: 8080,
        };
        self.send_encrypted_message(&switch_msg).await?;

        // 2. Wait for Peer ACK
        let ack = self.read_and_decrypt_message().await?;
        if let ProtocolMessage::Ack { .. } = ack {
            // OK
        } else {
            return Err(DeonError::HandshakeError);
        }

        // 3. Connect to TCP (Simulated endpoint)
        // In real device, this would be the peer's Wi-Fi IP. 
        // For simulation, we use localhost to connect to the listener in main.rs
        let new_transport = crate::transport::connect_tcp("127.0.0.1:8080").await?;
        
        // 4. Swap Transport
        self.transport = new_transport;
        info!("Transport switched to Wi-Fi TCP");
        
        Ok(())
    }

    // --- Helper Methods ---

    async fn send_cleartext_message(&mut self, msg: ProtocolMessage) -> Result<(), DeonError> {
        let payload = postcard::to_stdvec(&msg)?;
        self.transport.send(&payload).await
    }

    async fn send_encrypted_message(&mut self, msg: &ProtocolMessage) -> Result<(), DeonError> {
        let context = self.security_context.as_ref().ok_or(DeonError::InvalidState)?;
        
        let payload = postcard::to_stdvec(msg)?;
        
        // Encrypt (Auth Tag is appended by ChaCha20Poly1305)
        let (ciphertext, nonce) = context.encrypt(&payload, &[])?;
        
        // Wire Header
        let header = WireHeader {
            magic: MAGIC_BYTES,
            version: VERSION,
            flags: FLAG_ENCRYPTED,
            nonce,
        };
        
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        frame.extend_from_slice(&header.to_bytes());
        frame.extend_from_slice(&ciphertext);
        
        // Retry Loop for Transport Reliability (Exponential Backoff)
        let mut attempts = 0;
        let mut delay = 50; // Start with 50ms
        let max_retries = 3;

        loop {
            match self.transport.send(&frame).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    attempts += 1;
                    if attempts >= max_retries {
                        debug!("Transport send failed after {} attempts. Giving up.", attempts);
                        return Err(e);
                    }
                    
                    debug!("Transport send failed. Retrying in {}ms (Attempt {}/{})", delay, attempts, max_retries);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                    delay *= 2; // Exponential Backoff
                }
            }
        }
    }

    async fn read_and_decrypt_message(&mut self) -> Result<ProtocolMessage, DeonError> {
        let frame = self.transport.receive().await?;
        
        if frame.len() < HEADER_LEN {
            return Err(DeonError::ProtocolViolation);
        }

        let header = WireHeader::from_bytes(&frame).ok_or(DeonError::ProtocolViolation)?;
        
        if header.flags & FLAG_ENCRYPTED == 0 {
            return Err(DeonError::ProtocolViolation);
        }

        let context = self.security_context.as_ref().ok_or(DeonError::InvalidState)?;
        let ciphertext = &frame[HEADER_LEN..];

        let plaintext = context.decrypt(ciphertext, &header.nonce, &[])?;
        let msg = postcard::from_bytes(&plaintext)?;
        Ok(msg)
    }
}
