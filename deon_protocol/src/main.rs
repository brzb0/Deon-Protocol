use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

const DEFAULT_ADDRESS: &str = "127.0.0.1:8080";
const DEFAULT_PASSWORD: &str = "123456";

#[derive(Parser)]
#[command(name = "deon_protocol")]
#[command(version)]
#[command(about = "Secure file transfer with sane defaults", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file (default target: 127.0.0.1:8080)
    Send {
        /// File path to send
        file: PathBuf,

        /// Receiver address (ip:port)
        #[arg(default_value = DEFAULT_ADDRESS)]
        address: String,

        /// Shared PIN/password (or use DEON_PASSWORD env var)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Receive one file and save it to a folder
    #[command(alias = "recv")]
    Receive {
        /// Port to listen on
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

        /// Output folder (default: current directory)
        #[arg(short, long, default_value = ".")]
        out: PathBuf,

        /// Shared PIN/password (or use DEON_PASSWORD env var)
        #[arg(short, long)]
        password: Option<String>,
    },
}

fn resolve_password(password: Option<String>) -> String {
    password
        .or_else(|| std::env::var("DEON_PASSWORD").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_PASSWORD.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            file,
            address,
            password,
        } => {
            let password = resolve_password(password);
            info!("Sending '{}' to {}", file.display(), address);
            deon_protocol::send_file(&file, &address, &password).await?;
            info!("Transfer completed successfully");
        }

        Commands::Receive {
            port,
            out,
            password,
        } => {
            let password = resolve_password(password);
            info!("Waiting for file on port {}...", port);
            let saved_path = deon_protocol::receive_file(port, &password, &out).await?;
            info!("File saved at {}", saved_path.display());
        }
    }

    Ok(())
}
