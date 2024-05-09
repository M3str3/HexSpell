use crate::pe_errors::PeError;

pub fn extract_u64(buffer: &[u8], offset: usize) -> Result<u64, PeError> {
    buffer.get(offset..offset + 8)
          .ok_or(PeError::BufferOverflow)
          .and_then(|bytes| bytes.try_into().map_err(|_| PeError::BufferOverflow))
          .and_then(|bytes| Ok(u64::from_le_bytes(bytes)))
}

pub fn extract_u32(buffer: &[u8], offset: usize) -> Result<u32, PeError> {
    buffer.get(offset..offset + 4)
        .ok_or(PeError::BufferOverflow)
        .and_then(|bytes| bytes.try_into()
                    .map_err(|_| PeError::BufferOverflow)
                    .and_then(|bytes| Ok(u32::from_le_bytes(bytes))))
}

pub fn extract_u16(buffer: &[u8], offset: usize) -> Result<u16, PeError> {
    buffer.get(offset..offset + 2)
          .ok_or(PeError::BufferOverflow)
          .and_then(|bytes| bytes.try_into().map_err(|_| PeError::BufferOverflow))
          .and_then(|bytes| Ok(u16::from_le_bytes(bytes)))
}
