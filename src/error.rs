//! Error types for the policy library.

use std::path::PathBuf;

/// Errors that can occur in the policy library.
#[derive(Debug)]
pub enum PolicyError {
    /// Failed to read policy file
    FileRead {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to parse policy file
    ParseError { path: PathBuf, message: String },

    /// Invalid policy configuration
    InvalidPolicy { policy_id: String, reason: String },

    /// Regex compilation failed
    RegexError { pattern: String, message: String },

    /// Invalid keep expression
    InvalidKeepExpression { expression: String, reason: String },

    /// Field selection error
    FieldError { reason: String },

    /// Failed to compile Hyperscan database
    CompileError { reason: String },

    /// HTTP provider error
    HttpError(String),

    /// gRPC provider error
    GrpcError(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::FileRead { path, source } => {
                write!(f, "failed to read policy file {:?}: {}", path, source)
            }
            PolicyError::ParseError { path, message } => {
                write!(f, "failed to parse policy file {:?}: {}", path, message)
            }
            PolicyError::InvalidPolicy { policy_id, reason } => {
                write!(f, "invalid policy '{}': {}", policy_id, reason)
            }
            PolicyError::RegexError { pattern, message } => {
                write!(f, "invalid regex pattern '{}': {}", pattern, message)
            }
            PolicyError::InvalidKeepExpression { expression, reason } => {
                write!(f, "invalid keep expression '{}': {}", expression, reason)
            }
            PolicyError::FieldError { reason } => {
                write!(f, "field error: {}", reason)
            }
            PolicyError::CompileError { reason } => {
                write!(f, "failed to compile Hyperscan database: {}", reason)
            }
            PolicyError::HttpError(msg) => {
                write!(f, "HTTP provider error: {}", msg)
            }
            PolicyError::GrpcError(msg) => {
                write!(f, "gRPC provider error: {}", msg)
            }
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PolicyError::FileRead { source, .. } => Some(source),
            _ => None,
        }
    }
}
