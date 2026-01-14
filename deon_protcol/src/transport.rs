use async_trait::async_trait;
use crate::error::DeonError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use log::{debug};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Ble, // Kept for protocol compatibility, though not implemented in this CLI
    Wifi,
}

#[async_trait]
pub trait SecureTransport: Send + Sync {
    async fn send(&mut self, data: &[u8]) -> Result<(), DeonError>;
    async fn receive(&mut self) -> Result<Vec<u8>, DeonError>; // Returns full frame
    fn get_type(&self) -> TransportType;
    async fn close(&mut self) -> Result<(), DeonError>;
    // New: RSSI for gating
    async fn get_rssi(&self) -> Result<i32, DeonError>; 
}

/// Helper to connect to TCP
pub async fn connect_tcp(addr: &str) -> Result<Box<dyn SecureTransport>, DeonError> {
    let stream = TcpStream::connect(addr).await.map_err(|_| DeonError::Io)?;
    Ok(Box::new(TcpTransport::new(stream)))
}

/// TCP Implementation for Wi-Fi
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

#[async_trait]
impl SecureTransport for TcpTransport {
    async fn send(&mut self, data: &[u8]) -> Result<(), DeonError> {
        // Send length prefix for framing in TCP stream
        let len = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(data).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, DeonError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Safety check on max size
        if len > 50 * 1024 * 1024 { // 50MB limit check per frame (increased for larger chunks if needed)
            return Err(DeonError::ProtocolViolation);
        }

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }

    fn get_type(&self) -> TransportType {
        TransportType::Wifi
    }

    async fn close(&mut self) -> Result<(), DeonError> {
        self.stream.shutdown().await?;
        Ok(())
    }

    async fn get_rssi(&self) -> Result<i32, DeonError> {
        // RSSI not applicable for TCP/Wi-Fi in this context, return strong signal
        Ok(-30) 
    }
}

/// --- Exponential Backoff Strategy ---
pub struct RetryStrategy {
    initial_delay: u64,
    max_delay: u64,
    max_retries: u32,
}

impl RetryStrategy {
    pub fn new(initial_delay: u64, max_delay: u64, max_retries: u32) -> Self {
        Self {
            initial_delay,
            max_delay,
            max_retries,
        }
    }

    pub async fn execute<F, T, E>(&self, mut op: F) -> Result<T, E>
    where
        F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
    {
        let mut attempts = 0;
        let mut delay = self.initial_delay;
        
        // Removed random jitter to remove "rand" dependency if not strictly needed or keep it simple
        // If we need jitter, we need to ensure rand is imported.
        // For simplicity and "clean code", simple exponential backoff is often enough.
        
        loop {
            match op().await {
                Ok(value) => return Ok(value),
                Err(_) if attempts < self.max_retries => {
                    attempts += 1;
                    
                    debug!("Operation failed. Retrying in {}ms (Attempt {}/{})", delay, attempts, self.max_retries);
                    
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    
                    // Exponential Backoff
                    delay = (delay * 2).min(self.max_delay);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

use std::time::Duration;
