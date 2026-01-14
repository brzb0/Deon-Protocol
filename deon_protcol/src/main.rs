use deon_protocol::{
    DeonProtocol, transport::TcpTransport,
};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use log::info;

#[derive(Parser)]
#[command(name = "deon-protocol")]
#[command(version = "1.3.0")]
#[command(about = "Deon Protocol Secure File Transfer CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file to a remote peer
    Send {
        /// Path to the file to send
        #[arg(short, long)]
        file: String,

        /// Address of the receiver (IP:PORT)
        #[arg(short, long)]
        address: String,

        /// Shared PIN/Password for authentication
        #[arg(short, long)]
        password: String,
    },
    /// Receive a file from a remote peer
    Receive {
        /// Port to listen on
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

        /// Shared PIN/Password for authentication
        #[arg(short, long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Init Logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Send { file, address, password } => {
            run_sender(&file, &address, &password).await?;
        }
        Commands::Receive { port, password } => {
            run_receiver(port, &password).await?;
        }
    }

    Ok(())
}

async fn run_sender(file_path: &str, address: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Deon Protocol Sender...");
    
    // 1. Read File
    let path = std::path::Path::new(file_path);
    let filename = path.file_name().ok_or("Invalid filename")?.to_str().ok_or("Invalid filename")?;
    let mut file = tokio::fs::File::open(path).await?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).await?;
    info!("Read file '{}' ({} bytes)", filename, data.len());

    // 2. Connect
    info!("Connecting to {}...", address);
    let transport = deon_protocol::transport::connect_tcp(address).await?;

    // 3. Init Protocol
    let mut deon = DeonProtocol::new(transport);

    // 4. Handshake
    info!("Performing Secure Handshake...");
    deon.handshake(password).await?;
    info!("Handshake Successful!");

    // 5. Send File
    info!("Sending File...");
    deon.send_file(filename, &data).await?;
    info!("File Sent Successfully!");

    Ok(())
}

async fn run_receiver(port: u16, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Deon Protocol Receiver on port {}...", port);

    // 1. Listen
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Listening for connections...");

    // Accept one connection for this CLI tool
    let (socket, addr) = listener.accept().await?;
    info!("Accepted connection from: {}", addr);

    // 2. Setup Transport
    let transport = Box::new(TcpTransport::new(socket));

    // 3. Init Protocol
    let mut deon = DeonProtocol::new(transport);

    // 4. Handshake
    info!("Waiting for Secure Handshake...");
    deon.accept_handshake(password).await?;
    info!("Handshake Successful!");

    // 5. Receive File
    info!("Waiting for File...");
    deon.receive_file().await?;
    info!("File Received Successfully!");

    Ok(())
}
