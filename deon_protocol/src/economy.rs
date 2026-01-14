use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature, Verifier};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::error::DeonError;
use log::{info, debug, warn};

/// --- 1. Transaction Structure ---
/// Represents a value transfer or state change in the Deon Protocol.
/// Includes replay protection (nonce) and authenticity (signature).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub sender: [u8; 32],   // Ed25519 Public Key
    pub receiver: [u8; 32], // Ed25519 Public Key
    pub amount: u64,
    pub nonce: u64,         // Replay Protection
    pub signature: Option<Vec<u8>>,
}

impl Transaction {
    pub fn new(sender: [u8; 32], receiver: [u8; 32], amount: u64, nonce: u64) -> Self {
        Self {
            sender,
            receiver,
            amount,
            nonce,
            signature: None,
        }
    }

    /// Sign the transaction with the sender's private key.
    pub fn sign(&mut self, key_pair: &SigningKey) {
        let msg = self.get_signable_bytes();
        let signature: Signature = key_pair.sign(&msg);
        self.signature = Some(signature.to_bytes().to_vec());
    }

    /// Verify the transaction signature.
    pub fn verify(&self) -> Result<(), DeonError> {
        let sig_bytes = self.signature.as_ref().ok_or(DeonError::AuthFailed)?;
        if sig_bytes.len() != 64 {
            return Err(DeonError::AuthFailed);
        }
        
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);
        
        let public_key = VerifyingKey::from_bytes(&self.sender)
            .map_err(|_| DeonError::Crypto)?;

        let msg = self.get_signable_bytes();
        public_key.verify(&msg, &signature)
            .map_err(|_| DeonError::AuthFailed)
    }

    fn get_signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.receiver);
        buf.extend_from_slice(&self.amount.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf
    }
}

/// --- 2. Token State Management (Offline Ledger) ---
/// Tracks "Who has how much" and prevents double-spends via nonces.
pub struct Ledger {
    balances: Arc<Mutex<HashMap<[u8; 32], u64>>>,
    nonces: Arc<Mutex<HashMap<[u8; 32], u64>>>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            balances: Arc::new(Mutex::new(HashMap::new())),
            nonces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process a transaction: verify signature, check nonce, check balance, update state.
    pub fn process_transaction(&self, tx: &Transaction) -> Result<(), DeonError> {
        // 1. Verify Signature
        tx.verify()?;

        let mut balances = self.balances.lock().unwrap();
        let mut nonces = self.nonces.lock().unwrap();

        // 2. Replay Protection (Nonce Check)
        let current_nonce = nonces.entry(tx.sender).or_insert(0);
        if tx.nonce <= *current_nonce {
            warn!("Replay attack detected! Tx Nonce: {}, Current: {}", tx.nonce, *current_nonce);
            return Err(DeonError::AuthFailed); // Should be specific "ReplayDetected" error
        }

        // 3. Balance Check
        let sender_balance = balances.entry(tx.sender).or_insert(0);
        if *sender_balance < tx.amount {
            warn!("Insufficient funds: Has {}, Needs {}", *sender_balance, tx.amount);
            return Err(DeonError::ProtocolViolation); // InsufficientFunds
        }

        // 4. Update State (Atomically)
        *sender_balance -= tx.amount;
        let receiver_balance = balances.entry(tx.receiver).or_insert(0);
        *receiver_balance += tx.amount;
        
        // Update Nonce
        *current_nonce = tx.nonce;

        info!("Transaction processed: {} transferred", tx.amount);
        Ok(())
    }

    /// Debug helper to set balance (Minting)
    pub fn debug_mint(&self, account: [u8; 32], amount: u64) {
        let mut balances = self.balances.lock().unwrap();
        *balances.entry(account).or_insert(0) += amount;
    }

    pub fn get_balance(&self, account: &[u8; 32]) -> u64 {
        let balances = self.balances.lock().unwrap();
        *balances.get(account).unwrap_or(&0)
    }
}

/// --- 3. Settlement Layer Interface ---
/// Defines how the offline protocol syncs with a blockchain when online.
#[async_trait::async_trait]
pub trait SettlementLayer: Send + Sync {
    /// Submit a batch of offline transactions to the blockchain.
    async fn settle_batch(&self, transactions: Vec<Transaction>) -> Result<[u8; 32], DeonError>;
    
    /// Verify if a transaction is finalized on-chain.
    async fn is_finalized(&self, tx_hash: &[u8]) -> Result<bool, DeonError>;
}

/// Mock implementation for testing/docs
pub struct MockBlockchain;

#[async_trait::async_trait]
impl SettlementLayer for MockBlockchain {
    async fn settle_batch(&self, transactions: Vec<Transaction>) -> Result<[u8; 32], DeonError> {
        info!("Settling {} transactions to MockBlockchain...", transactions.len());
        Ok([0xEE; 32]) // Mock Tx Hash
    }

    async fn is_finalized(&self, _tx_hash: &[u8]) -> Result<bool, DeonError> {
        Ok(true)
    }
}
