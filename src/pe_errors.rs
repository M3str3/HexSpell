use std::array::TryFromSliceError;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PeError {
    #[error("Invalid PE file.")]
    InvalidPeFile,
    #[error("Data out of bounds.")]
    BufferOverflow,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Error converting slice to array: {0}")]
    SliceConversion(#[from] TryFromSliceError),
    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),
}

pub type Result<T> = std::result::Result<T, PeError>;