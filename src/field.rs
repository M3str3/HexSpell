//! Abstraction for editable fields inside binary buffers.
//!
//! Many binary structures store numeric or string values at fixed offsets.
//! The [`Field`] type pairs such a value with its location and size in the
//! original byte slice, allowing callers to modify the data in place while
//! enforcing bounds and value‑size checks.

use crate::errors::FileParseError;

#[derive(Debug, Clone, Copy)]
pub struct Field<T> {
    pub value: T,
    pub offset: usize,
    pub size: usize,
}

impl<T> Field<T> {
    pub fn new(value: T, offset: usize, size: usize) -> Self {
        Field {
            value,
            offset,
            size,
        }
    }
}

impl Field<u64> {
    /// Updates the buffer at the specified offset with the new value for u64.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u64) -> Result<(), FileParseError> {
        if self.size < std::mem::size_of::<u64>() {
            let bits = (self.size * 8) as u32;
            if (new_value >> bits) != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
        }

        self.value = new_value;
        let bytes = new_value.to_le_bytes();
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
        Ok(())
    }
}

impl Field<u32> {
    /// Updates the buffer at the specified offset with the new value for u32.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u32) -> Result<(), FileParseError> {
        if self.size < std::mem::size_of::<u32>() {
            let bits = (self.size * 8) as u32;
            if (new_value >> bits) != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
        }

        self.value = new_value;
        let bytes = new_value.to_le_bytes();
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
        Ok(())
    }
}
impl Field<u16> {
    /// Updates the buffer at the specified offset with the new value for u16.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u16) -> Result<(), FileParseError> {
        if self.size < std::mem::size_of::<u16>() {
            let bits = (self.size * 8) as u32;
            if (new_value >> bits) != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
        }

        self.value = new_value;
        let bytes = new_value.to_le_bytes();
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
        Ok(())
    }
}

impl Field<String> {
    /// Updates the buffer at the specified offset with the new UTF-8 encoded string.
    pub fn update(&mut self, buffer: &mut [u8], new_value: &str) -> Result<(), FileParseError> {
        self.value = new_value.to_string();
        let bytes: &[u8] = new_value.as_bytes();
        if bytes.len() > self.size {
            return Err(FileParseError::BufferOverflow);
        }

        buffer[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
        if bytes.len() < self.size {
            buffer[self.offset + bytes.len()..self.offset + self.size].fill(0u8);
        }
        Ok(())
    }
}
