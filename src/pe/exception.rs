//! Exception directory (`RUNTIME_FUNCTION` entries on x64).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::extract_u32;

/// `IMAGE_RUNTIME_FUNCTION_ENTRY` — 12 bytes (`.pdata` on x64).
pub struct RuntimeFunction {
    /// Start RVA of the function (`BeginAddress`).
    pub begin_address: Field<u32>,
    /// End RVA of the function (`EndAddress`).
    pub end_address: Field<u32>,
    /// RVA of the unwind info (`UnwindData`).
    pub unwind_data: Field<u32>,
}

impl RuntimeFunction {
    /// Size of `IMAGE_RUNTIME_FUNCTION_ENTRY` in bytes.
    pub const SIZE: usize = 12;

    /// Parses one runtime function entry at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(RuntimeFunction {
            begin_address: Field::new(extract_u32(buffer, offset)?, offset, 4),
            end_address: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            unwind_data: Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4),
        })
    }
}

/// Parsed exception / runtime function directory.
pub struct ExceptionDirectory {
    /// Absolute file offset of the first entry.
    pub offset: usize,
    /// Runtime function entries.
    pub entries: Vec<RuntimeFunction>,
}

impl ExceptionDirectory {
    /// Parses `RUNTIME_FUNCTION` records from the exception data directory.
    pub fn parse(buffer: &[u8], offset: usize, size: usize) -> Result<Self, FileParseError> {
        if size == 0 {
            return Ok(ExceptionDirectory {
                offset,
                entries: Vec::new(),
            });
        }

        if !size.is_multiple_of(RuntimeFunction::SIZE) {
            return Err(FileParseError::InvalidFileFormat);
        }

        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let count = size / RuntimeFunction::SIZE;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            entries.push(RuntimeFunction::parse(
                buffer,
                offset + i * RuntimeFunction::SIZE,
            )?);
        }

        Ok(ExceptionDirectory { offset, entries })
    }
}
