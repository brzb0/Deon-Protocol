use async_trait::async_trait;
use crate::error::DeonError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Ble,
    Wifi,
}

#[async_trait]
pub trait SecureTransport: Send + Sync {
    async fn send(&mut self, data: &[u8]) -> Result<(), DeonError>;
    async fn receive(&mut self) -> Result<Vec<u8>, DeonError>; // Returns full frame
    fn get_type(&self) -> TransportType;
    async fn close(&mut self) -> Result<(), DeonError>;
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
        // Send length prefix for framing in TCP stream if needed, 
        // or rely on the Protocol Header Magic Bytes for delimiters.
        // For reliability, length-prefixed is safer for TCP.
        let len = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await.map_err(DeonError::Io)?;
        self.stream.write_all(data).await.map_err(DeonError::Io)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, DeonError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await.map_err(DeonError::Io)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Safety check on max size
        if len > 10 * 1024 * 1024 { // 10MB limit check
            return Err(DeonError::ProtocolViolation("Frame too large".into()));
        }

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await.map_err(DeonError::Io)?;
        Ok(buf)
    }

    fn get_type(&self) -> TransportType {
        TransportType::Wifi
    }

    async fn close(&mut self) -> Result<(), DeonError> {
        self.stream.shutdown().await.map_err(DeonError::Io)
    }
}

/// Mock BLE Implementation (since no hardware access)
pub struct BleTransport {
    // In real implementation: btleplug::peripheral::Peripheral
    // For simulation: we can use channels or just a placeholder
    connected: bool,
}

impl BleTransport {
    pub fn new() -> Self {
        Self { connected: true }
    }
}

#[async_trait]
impl SecureTransport for BleTransport {
    async fn send(&mut self, _data: &[u8]) -> Result<(), DeonError> {
        // Simulating BLE MTU fragmentation would go here
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, DeonError> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Return a dummy KeepAlive or similar for test
        Ok(vec![]) 
    }

    fn get_type(&self) -> TransportType {
        TransportType::Ble
    }
    
    async fn close(&mut self) -> Result<(), DeonError> {
        self.connected = false;
        Ok(())
    }
}

/// Exponential Back-off with Jitter Helper
pub struct RetryStrategy {
    base_delay: Duration,
    max_delay: Duration,
    max_retries: u32,
}

impl RetryStrategy {
    pub fn new(base_ms: u64, max_ms: u64, retries: u32) -> Self {
        Self {
            base_delay: Duration::from_millis(base_ms),
            max_delay: Duration::from_millis(max_ms),
            max_retries: retries,
        }
    }

    pub async fn execute<F, T, E, Fut>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        let mut retries = 0;
        loop {
            match operation().await {
                Ok(val) => return Ok(val),
                Err(e) => {
                    if retries >= self.max_retries {
                        return Err(e);
                    }
                    
                    let exp_factor = 2u32.pow(retries);
                    let mut delay = self.base_delay * exp_factor;
                    if delay > self.max_delay {
                        delay = self.max_delay;
                    }
                    
                    // Add Jitter (0 to 100ms random)
                    let jitter = rand::thread_rng().gen_range(0..100);
                    delay += Duration::from_millis(jitter);

                    tokio::time::sleep(delay).await;
                    retries += 1;
                }
            }
        }
    }
}
