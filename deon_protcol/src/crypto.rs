use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key,
};
use async_trait::async_trait;
use crate::error::DeonError;
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};
use argon2::{
    password_hash::{
        rand_core::OsRng as ArgonOsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use tokio::time::Instant;

/// --- 1. Epoch-Based Nonce ---
/// Structure: [Epoch (4 bytes) | Counter (8 bytes)] = 12 bytes (96 bits)
#[derive(Debug)]
pub struct EpochNonce {
    epoch: u32,
    counter: Arc<Mutex<u64>>,
}

impl EpochNonce {
    pub fn new(_is_initiator: bool) -> Self {
        // Epoch derived from system time to ensure uniqueness across restarts
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let epoch = since_the_epoch.as_secs() as u32;

        // Initiator starts even, Responder starts odd (or use separate keys)
        // Here we use simple counter + direction separation if sharing keys.
        // But for robust security, we usually derive separate keys for RX/TX.
        // Assuming separate keys (recommended), we just start at 0.
        Self {
            epoch,
            counter: Arc::new(Mutex::new(0)),
        }
    }

    pub fn next(&self) -> [u8; 12] {
        let mut guard = self.counter.lock().unwrap();
        *guard += 1;
        let count = *guard;
        
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.epoch.to_be_bytes());
        nonce[4..12].copy_from_slice(&count.to_be_bytes());
        nonce
    }
}

/// --- 2. Token Bucket Filter (DoS Protection) ---
pub struct TokenBucket {
    capacity: u32,
    tokens: Arc<Mutex<f64>>,
    last_refill: Arc<Mutex<Instant>>,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: Arc::new(Mutex::new(capacity as f64)),
            last_refill: Arc::new(Mutex::new(Instant::now())),
            refill_rate,
        }
    }

    pub fn consume(&self, amount: u32) -> Result<(), DeonError> {
        let mut tokens = self.tokens.lock().unwrap();
        let mut last_refill = self.last_refill.lock().unwrap();
        
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        
        // Refill
        let new_tokens = elapsed * self.refill_rate;
        *tokens = (*tokens + new_tokens).min(self.capacity as f64);
        *last_refill = now;

        if *tokens >= amount as f64 {
            *tokens -= amount as f64;
            Ok(())
        } else {
            Err(DeonError::RateLimited)
        }
    }
}

/// --- 3. Session Resumption Ticket ---
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResumptionTicket {
    pub key: [u8; 32],
    pub expiry: u64, // Timestamp
}

/// --- 4. Hardware-Backed Key Storage ---
#[async_trait]
pub trait KeyStorage: Send + Sync {
    async fn get_master_key(&self) -> Result<Vec<u8>, DeonError>;
    async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, DeonError>;
}

pub struct FileKeyStorage {
    _file_path: String,
    device_id: String,
}

impl FileKeyStorage {
    pub fn new(file_path: &str, device_id: &str) -> Self {
        Self {
            _file_path: file_path.to_string(),
            device_id: device_id.to_string(),
        }
    }
}

#[async_trait]
impl KeyStorage for FileKeyStorage {
    async fn get_master_key(&self) -> Result<Vec<u8>, DeonError> {
        // Argon2id for Device Binding
        // In real usage, we would read a salt from DB. Here we generate/hardcode for mock.
        let salt = SaltString::generate(&mut ArgonOsRng);
        let argon2 = Argon2::default();
        
        // Use device_id as password component
        let password = self.device_id.as_bytes();
        let password_hash = argon2.hash_password(password, &salt)
            .map_err(|_| DeonError::Crypto)?;
            
        // Derive 32 bytes from hash (simplification)
        // In reality, use the output hash bytes as the key.
        let hash_str = password_hash.to_string();
        let mut key = [0u8; 32];
        // Just fill with hash bytes
        let bytes = hash_str.as_bytes();
        for i in 0..32 {
            if i < bytes.len() { key[i] = bytes[i]; }
        }
        
        Ok(key.to_vec())
    }

    async fn sign_data(&self, _data: &[u8]) -> Result<Vec<u8>, DeonError> {
        Ok(vec![0xBB; 64])
    }
}

/// --- 5. Security Context ---
pub struct SecurityContext {
    cipher_tx: ChaCha20Poly1305, // Key for Sending
    cipher_rx: ChaCha20Poly1305, // Key for Receiving
    nonce_tx: EpochNonce,
    // We track last seen counter for RX replay protection
    _rx_replay_bitmap: Arc<Mutex<u64>>, // Simple sliding window could go here, for now just max counter
    rx_last_counter: Arc<Mutex<u64>>,
    pub token_bucket: TokenBucket,
}

impl SecurityContext {
    pub fn new(shared_secret: [u8; 32], is_initiator: bool) -> Self {
        // Derive TWO keys: one for TX, one for RX
        let hk = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut okm = [0u8; 64];
        hk.expand(b"deon_v1.1_session_keys", &mut okm).unwrap();
        
        let (key1, key2) = okm.split_at(32);
        
        // Initiator: TX=Key1, RX=Key2
        // Responder: TX=Key2, RX=Key1
        let (my_tx_key, my_rx_key) = if is_initiator {
            (key1, key2)
        } else {
            (key2, key1)
        };

        Self {
            cipher_tx: ChaCha20Poly1305::new(Key::from_slice(my_tx_key)),
            cipher_rx: ChaCha20Poly1305::new(Key::from_slice(my_rx_key)),
            nonce_tx: EpochNonce::new(is_initiator),
            _rx_replay_bitmap: Arc::new(Mutex::new(0)),
            rx_last_counter: Arc::new(Mutex::new(0)),
            token_bucket: TokenBucket::new(100, 10.0), // Cap 100, 10/sec
        }
    }

    pub fn encrypt(&self, data: &[u8], associated_data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), DeonError> {
        // Check Rate Limit for TX (optional, but good for battery)
        self.token_bucket.consume(1)?;

        let nonce = self.nonce_tx.next();
        let payload = Payload {
            msg: data,
            aad: associated_data,
        };

        let ciphertext = self.cipher_tx.encrypt(&nonce.into(), payload)
            .map_err(|_| DeonError::Crypto)?;

        Ok((ciphertext, nonce))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12], associated_data: &[u8]) -> Result<Vec<u8>, DeonError> {
        // DoS Protection: Consume tokens BEFORE crypto
        // If auth fails, we consume 10 tokens (penalty)
        // Since we can't know if it fails before trying, we consume 1 cost now, 
        // and if fail, we consume 9 more?
        // Or better: Just consume standard cost. 
        // User req: "Cada fallo de autenticación Poly1305 consume 10 tokens (penalización)."
        // We check if we have enough for base cost.
        self.token_bucket.consume(1)?;

        // Replay Check
        let _epoch = u32::from_be_bytes(nonce[0..4].try_into().unwrap());
        let counter = u64::from_be_bytes(nonce[4..12].try_into().unwrap());
        
        // Check Epoch?
        // In this simple model, we assume session is fresh. 
        // If we want strict replay protection, we verify counter > last_counter.
        {
            let mut last = self.rx_last_counter.lock().unwrap();
            if counter <= *last && *last != 0 {
                return Err(DeonError::Crypto); // Replay
            }
            *last = counter;
        }

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        match self.cipher_rx.decrypt(nonce.into(), payload) {
            Ok(pt) => Ok(pt),
            Err(_) => {
                // Penalize
                let _ = self.token_bucket.consume(9); // 10 total
                Err(DeonError::AuthFailed)
            }
        }
    }
}
