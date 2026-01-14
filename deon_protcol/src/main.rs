use deon_protcol::{
    DeonProtocol, SecureTransport, TransportType, DeonError,
    types::{ProtocolMessage, WireHeader, MAGIC_BYTES, VERSION, FLAG_ENCRYPTED, HEADER_LEN},
    crypto::{HandshakeManager, SecurityContext},
};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use log::info;
use x25519_dalek::PublicKey;

// --- Simulated Transport (Acts as the other device) ---
struct SimulatedPeerTransport {
    incoming_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    handshake_mgr: HandshakeManager,
    security_context: Option<SecurityContext>,
    step: Arc<Mutex<usize>>,
}

impl SimulatedPeerTransport {
    fn new() -> Self {
        Self {
            incoming_queue: Arc::new(Mutex::new(VecDeque::new())),
            handshake_mgr: HandshakeManager::new(),
            security_context: None,
            step: Arc::new(Mutex::new(0)),
        }
    }

    fn push_response(&self, msg: Vec<u8>) {
        self.incoming_queue.lock().unwrap().push_back(msg);
    }
}

#[async_trait]
impl SecureTransport for SimulatedPeerTransport {
    async fn send(&mut self, data: &[u8]) -> Result<(), DeonError> {
        info!("[Peer] Received {} bytes", data.len());
        
        let mut step = self.step.lock().unwrap();
        
        // Simple State Machine for the Mock Peer
        match *step {
            0 => {
                // Expecting Cleartext Hello
                let msg: ProtocolMessage = postcard::from_bytes(data).map_err(|e| DeonError::Serialization(e.to_string()))?;
                if let ProtocolMessage::Hello { public_key, .. } = msg {
                    info!("[Peer] Got Hello. Sending HelloAck...");
                    
                    // Derive Shared Secret
                    let peer_pub = PublicKey::from(public_key);
                    let shared_secret = self.handshake_mgr.derive_shared_secret(peer_pub);
                    
                    // Init Security Context (Peer is responder)
                    self.security_context = Some(SecurityContext::new(shared_secret, false));

                    // Send Hello back (Cleartext for this simplistic PAKE demo, usually blinded)
                    let response = ProtocolMessage::Hello {
                        public_key: self.handshake_mgr.my_public.to_bytes(),
                        device_id: "DeviceB".to_string(),
                    };
                    let resp_bytes = postcard::to_stdvec(&response).unwrap();
                    self.push_response(resp_bytes);
                    
                    *step += 1;
                }
            }
            1 => {
                // Expecting Encrypted Ping
                // Need to decrypt
                let header = WireHeader::from_bytes(data).unwrap();
                let ciphertext = &data[HEADER_LEN..];
                let ctx = self.security_context.as_ref().unwrap();
                
                let plaintext = ctx.decrypt(ciphertext, &header.nonce, &[]).expect("Peer failed to decrypt");
                let msg: ProtocolMessage = postcard::from_bytes(&plaintext).unwrap();
                
                if let ProtocolMessage::Ping = msg {
                     info!("[Peer] Got Ping. Sending Encrypted Pong...");
                     
                     // Send Pong
                     let pong = ProtocolMessage::Pong;
                     let payload = postcard::to_stdvec(&pong).unwrap();
                     let (ct, nonce) = ctx.encrypt(&payload, &[]).unwrap();
                     
                     let mut frame = Vec::new();
                     let h = WireHeader { magic: MAGIC_BYTES, version: VERSION, flags: FLAG_ENCRYPTED, nonce };
                     frame.extend_from_slice(&h.to_bytes());
                     frame.extend_from_slice(&ct);
                     
                     self.push_response(frame);
                     *step += 1;
                }
            }
            _ => {
                // Handle Generic Encrypted Messages (File Transfer)
                let header = WireHeader::from_bytes(data).unwrap();
                let ciphertext = &data[HEADER_LEN..];
                let ctx = self.security_context.as_ref().unwrap();
                
                let plaintext = ctx.decrypt(ciphertext, &header.nonce, &[]).expect("Peer failed to decrypt");
                let msg: ProtocolMessage = postcard::from_bytes(&plaintext).unwrap();
                
                match msg {
                    ProtocolMessage::FileHeader { filename, size, .. } => {
                         info!("[Peer] Receiving File: {} ({} bytes)", filename, size);
                    }
                    ProtocolMessage::FileChunk { offset, data } => {
                        info!("[Peer] Got Chunk at offset {}. Size: {}", offset, data.len());
                    }
                    ProtocolMessage::SwitchToWifi { .. } => {
                         info!("[Peer] Switch to Wifi Requested. Sending ACK (Encrypted).");
                         // Send Ack
                         let ack = ProtocolMessage::Ack { id: 1 };
                         let payload = postcard::to_stdvec(&ack).unwrap();
                         let (ct, nonce) = ctx.encrypt(&payload, &[]).unwrap();
                         
                         let mut frame = Vec::new();
                         let h = WireHeader { magic: MAGIC_BYTES, version: VERSION, flags: FLAG_ENCRYPTED, nonce };
                         frame.extend_from_slice(&h.to_bytes());
                         frame.extend_from_slice(&ct);
                         
                         self.push_response(frame);
                         
                         // In this simulation, we don't actually switch the transport object, 
                         // but we could log it.
                    }
                    _ => info!("[Peer] Got other message: {:?}", msg),
                }
            }
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, DeonError> {
        // Wait until there is data
        loop {
            {
                let mut queue = self.incoming_queue.lock().unwrap();
                if let Some(data) = queue.pop_front() {
                    return Ok(data);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn get_type(&self) -> TransportType {
        TransportType::Ble
    }

    async fn close(&mut self) -> Result<(), DeonError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Init Logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Starting Deon Protocol Simulation...");

    // 1. Setup Transport
    let transport = Box::new(SimulatedPeerTransport::new());

    // 2. Init Protocol
    let mut deon = DeonProtocol::new(transport);

    // 3. Handshake
    info!("--- Step 1: Handshake ---");
    deon.handshake("123456").await?;
    
    // 4. Send Small File
    info!("--- Step 2: Send Small File ---");
    let small_data = b"Hello Secure World".to_vec();
    deon.send_file("small.txt", &small_data).await?;

    // 5. Send Large File (Trigger Switch)
    info!("--- Step 3: Send Large File (Trigger Handover) ---");
    // Create dummy 70KB data
    let large_data = vec![0u8; 70 * 1024]; 
    
    // Note: The simulated transport above doesn't actually handle the TCP connect logic in `perform_wifi_handover`.
    // The protocol code tries to connect to 192.168.1.50:8080.
    // Since that doesn't exist, it will fail with IO Error.
    // For this test, we expect it to fail at the TCP connect step, or we can mock that too if we could inject a factory.
    // Since we hardcoded the TCP connect in `protocol.rs`, it will fail.
    // We will catch the error and print it, proving the logic tried to switch.
    
    match deon.send_file("large.bin", &large_data).await {
        Ok(_) => info!("Large file sent successfully"),
        Err(e) => info!("Large file transfer stopped as expected (No real TCP listener): {}", e),
    }

    Ok(())
}
