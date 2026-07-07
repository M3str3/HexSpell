//! Debug directory entries (`IMAGE_DEBUG_DIRECTORY`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

/// `IMAGE_DEBUG_TYPE_CODEVIEW`.
pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;

/// `IMAGE_DEBUG_DIRECTORY` — 28 bytes.
pub struct DebugDirectoryEntry {
    /// Characteristics (reserved, must be zero).
    pub characteristics: Field<u32>,
    /// Time/date stamp.
    pub time_date_stamp: Field<u32>,
    /// Major format version.
    pub major_version: Field<u16>,
    /// Minor format version.
    pub minor_version: Field<u16>,
    /// Debug type (`IMAGE_DEBUG_TYPE_*`).
    pub debug_type: Field<u32>,
    /// Size of the debug data block.
    pub size_of_data: Field<u32>,
    /// File offset of the debug data (not an RVA).
    pub pointer_to_raw_data: Field<u32>,
    /// RVA of the debug data when mapped.
    pub address_of_raw_data: Field<u32>,
}

/// Parsed debug directory.
pub struct DebugDirectory {
    /// Absolute file offset of the first entry.
    pub offset: usize,
    /// Debug directory entries.
    pub entries: Vec<DebugDirectoryEntry>,
}

impl DebugDirectoryEntry {
    /// Size of `IMAGE_DEBUG_DIRECTORY` in bytes.
    pub const SIZE: usize = 28;

    /// Parses one debug directory entry at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(DebugDirectoryEntry {
            characteristics: Field::new(extract_u32(buffer, offset)?, offset, 4),
            time_date_stamp: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            major_version: Field::new(extract_u16(buffer, offset + 8)?, offset + 8, 2),
            minor_version: Field::new(extract_u16(buffer, offset + 10)?, offset + 10, 2),
            debug_type: Field::new(extract_u32(buffer, offset + 12)?, offset + 12, 4),
            size_of_data: Field::new(extract_u32(buffer, offset + 16)?, offset + 16, 4),
            pointer_to_raw_data: Field::new(extract_u32(buffer, offset + 20)?, offset + 20, 4),
            address_of_raw_data: Field::new(extract_u32(buffer, offset + 24)?, offset + 24, 4),
        })
    }

    /// Reads raw debug data bytes from `buffer` using [`Self::pointer_to_raw_data`].
    pub fn raw_data<'a>(&self, buffer: &'a [u8]) -> Result<&'a [u8], FileParseError> {
        let start = self.pointer_to_raw_data.value as usize;
        let end = start
            .checked_add(self.size_of_data.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        buffer.get(start..end).ok_or(FileParseError::BufferOverflow)
    }
}

impl DebugDirectory {
    /// Parses debug directory entries from `buffer`.
    pub fn parse(buffer: &[u8], offset: usize, size: usize) -> Result<Self, FileParseError> {
        if size == 0 {
            return Ok(DebugDirectory {
                offset,
                entries: Vec::new(),
            });
        }

        if !size.is_multiple_of(DebugDirectoryEntry::SIZE) {
            return Err(FileParseError::InvalidFileFormat);
        }

        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let count = size / DebugDirectoryEntry::SIZE;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            entries.push(DebugDirectoryEntry::parse(
                buffer,
                offset + i * DebugDirectoryEntry::SIZE,
            )?);
        }

        Ok(DebugDirectory { offset, entries })
    }
}
