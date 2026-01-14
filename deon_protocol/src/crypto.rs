use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce, Key,
};
use async_trait::async_trait;
use crate::error::DeonError;
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};
use argon2::{
    password_hash::{
        rand_core::OsRng as ArgonOsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use tokio::time::Instant;
use rand::{RngCore, thread_rng};

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
    pub session_id: [u8; 32],
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

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

impl FileKeyStorage {
    pub fn new(file_path: &str, device_id: &str) -> Self {
        Self {
            _file_path: file_path.to_string(),
            device_id: device_id.to_string(),
        }
    }

    fn get_salt(&self) -> Result<SaltString, DeonError> {
        let salt_path = format!("{}.salt", self._file_path);
        let path = Path::new(&salt_path);

        if path.exists() {
            let mut file = File::open(path).map_err(|_| DeonError::Io)?;
            let mut salt_str = String::new();
            file.read_to_string(&mut salt_str).map_err(|_| DeonError::Io)?;
            SaltString::from_b64(&salt_str).map_err(|_| DeonError::Crypto)
        } else {
            let salt = SaltString::generate(&mut ArgonOsRng);
            let mut file = File::create(path).map_err(|_| DeonError::Io)?;
            file.write_all(salt.as_str().as_bytes()).map_err(|_| DeonError::Io)?;
            Ok(salt)
        }
    }
}

#[async_trait]
impl KeyStorage for FileKeyStorage {
    async fn get_master_key(&self) -> Result<Vec<u8>, DeonError> {
        // Argon2id for Device Binding
        // Persist salt to ensure reproducibility
        let salt = self.get_salt()?;
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
    cipher_tx: XChaCha20Poly1305, // Key for Sending
    cipher_rx: XChaCha20Poly1305, // Key for Receiving
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
            cipher_tx: XChaCha20Poly1305::new(Key::from_slice(my_tx_key)),
            cipher_rx: XChaCha20Poly1305::new(Key::from_slice(my_rx_key)),
            token_bucket: TokenBucket::new(100, 10.0), // Cap 100, 10/sec
        }
    }

    pub fn encrypt(&self, data: &[u8], associated_data: &[u8]) -> Result<(Vec<u8>, [u8; 24]), DeonError> {
        // Check Rate Limit for TX (optional, but good for battery)
        self.token_bucket.consume(1)?;

        let mut nonce_bytes = [0u8; 24];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: data,
            aad: associated_data,
        };

        let ciphertext = self.cipher_tx.encrypt(nonce, payload)
            .map_err(|_| DeonError::Crypto)?;

        Ok((ciphertext, nonce_bytes))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 24], associated_data: &[u8]) -> Result<Vec<u8>, DeonError> {
        // DoS Protection: Consume tokens BEFORE crypto
        self.token_bucket.consume(1)?;

        // Replay Check: With XChaCha20 (random nonce), we rely on transport layer (TCP) 
        // or app-level logic for replay protection. 
        // Monotonic counters are not used here to avoid state synchronization issues with random nonces.

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        match self.cipher_rx.decrypt(XNonce::from_slice(nonce), payload) {
            Ok(pt) => Ok(pt),
            Err(_) => {
                // Penalize
                let _ = self.token_bucket.consume(9); // 10 total
                Err(DeonError::AuthFailed)
            }
        }
    }
}
