use std::io;
use std::fmt;

#[derive(Debug)]
pub enum FileParseError {
    Io(io::Error),
    InvalidFileFormat,
    BufferOverflow,
    SliceConversionError,
    UnsupportedFeature(String),
}

impl fmt::Display for FileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileParseError::Io(err) => write!(f, "I/O error: {}", err),
            FileParseError::InvalidFileFormat => write!(f, "Invalid file format."),
            FileParseError::BufferOverflow => write!(f, "Data out of bounds."),
            FileParseError::SliceConversionError => write!(f, "Error converting slice to array."),
            FileParseError::UnsupportedFeature(feature) => write!(f, "Unsupported feature: {}", feature),
        }
    }
}

impl From<io::Error> for FileParseError {
    fn from(err: io::Error) -> Self {
        FileParseError::Io(err)
    }
}
impl std::error::Error for FileParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FileParseError::Io(err) => Some(err),
            _ => None,
        }
    }
}
pub type Result<T> = std::result::Result<T, FileParseError>;
