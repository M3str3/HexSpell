use crate::errors::FileParseError;

pub fn extract_u64(buffer: &[u8], offset: usize) -> Result<u64, FileParseError> {
    buffer
        .get(offset..offset + 8)
        .ok_or(FileParseError::BufferOverflow)
        .and_then(|bytes| bytes.try_into().map_err(|_| FileParseError::BufferOverflow)).map(u64::from_le_bytes)
}

pub fn extract_u32(buffer: &[u8], offset: usize) -> Result<u32, FileParseError> {
    buffer
        .get(offset..offset + 4)
        .ok_or(FileParseError::BufferOverflow)
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|_| FileParseError::BufferOverflow).map(u32::from_le_bytes)
        })
}

pub fn extract_u16(buffer: &[u8], offset: usize) -> Result<u16, FileParseError> {
    buffer
        .get(offset..offset + 2)
        .ok_or(FileParseError::BufferOverflow)
        .and_then(|bytes| bytes.try_into().map_err(|_| FileParseError::BufferOverflow)).map(u16::from_le_bytes)
}
