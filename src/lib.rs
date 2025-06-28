use std::fmt;

pub mod events;

pub type Result<T> = std::result::Result<T, PositronError>;

#[derive(Debug)]
pub enum PositronError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Message(String),
}

impl fmt::Display for PositronError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PositronError::Io(e) => write!(f, "I/O error: {}", e),
            PositronError::Json(e) => write!(f, "JSON error: {}", e),
            PositronError::Message(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for PositronError {
    
}

impl From<std::io::Error> for PositronError {
    fn from(err: std::io::Error) -> Self {
        PositronError::Io(err)
    }
}

impl From<serde_json::Error> for PositronError {
    fn from(err: serde_json::Error) -> Self {
        PositronError::Json(err)
    }
}

pub fn init_logging() {
    tracing_subscriber::fmt().init();
    tracing::info!("Positron-EDR Initialized...");
}