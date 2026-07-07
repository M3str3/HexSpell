//! Mach-O section relocation entries (`relocation_info` / `scattered_relocation_info`).
//!
//! Relocations are stored at the file offset given by a section's `reloff` field. Each record is
//! either 8 bytes (`relocation_info`) or 8 bytes (`scattered_relocation_info` when the high bit of
//! the first word is set).

use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// High bit of `r_address` — marks a [`ScatteredRelocationInfo`] record.
pub const R_SCATTERED: u32 = 0x8000_0000;

/// `relocation_info` — 8 bytes, used when `r_address` does not have [`R_SCATTERED`] set.
#[derive(Debug)]
pub struct RelocationInfo {
    /// Section-relative byte offset (`r_address`).
    pub r_address: Field<i32>,
    /// Symbol table index (`r_symbolnum`, low 24 bits).
    pub r_symbolnum: Field<u32>,
    /// `true` when `r_pcrel` is set.
    pub r_pcrel: bool,
    /// Log2 of the width in bytes (`r_length`: 0=1, 1=2, 2=4, 3=8).
    pub r_length: u8,
    /// `true` when `r_extern` is set (symbol index refers to the symbol table).
    pub r_extern: bool,
    /// Relocation type (`r_type`, low 4 bits of the second word).
    pub r_type: u8,
}

/// `scattered_relocation_info` — 8 bytes, used when `r_address` has [`R_SCATTERED`] set.
#[derive(Debug)]
pub struct ScatteredRelocationInfo {
    /// Section-relative byte offset (`r_address`, low 24 bits).
    pub r_address: Field<u32>,
    /// Relocation type (`r_type`).
    pub r_type: Field<u8>,
    /// Log2 of the width in bytes (`r_length`).
    pub r_length: Field<u8>,
    /// `true` when `r_pcrel` is set.
    pub r_pcrel: bool,
    /// Absolute value (`r_value`).
    pub r_value: Field<i32>,
}

/// One relocation record — regular or scattered.
#[derive(Debug)]
pub enum RelocationEntry {
    /// Standard `relocation_info`.
    Regular(RelocationInfo),
    /// Legacy `scattered_relocation_info`.
    Scattered(ScatteredRelocationInfo),
}

impl RelocationEntry {
    /// Size of one relocation record in bytes.
    pub const SIZE: usize = 8;

    /// Parses one relocation at `offset`.
    pub fn parse(buffer: &[u8], offset: usize, order: ByteOrder) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        let word0 = order.read_u32(buffer, offset)?;
        if word0 & R_SCATTERED != 0 {
            let word1 = order.read_u32(buffer, offset + 4)?;
            Ok(RelocationEntry::Scattered(ScatteredRelocationInfo {
                r_address: Field::new(word0 & 0x00FF_FFFF, offset, 4),
                r_type: Field::new(((word0 >> 24) & 0x0F) as u8, offset, 4),
                r_length: Field::new(((word0 >> 28) & 0x03) as u8, offset, 4),
                r_pcrel: (word0 >> 30) & 1 != 0,
                r_value: Field::new(word1 as i32, offset + 4, 4),
            }))
        } else {
            let word1 = order.read_u32(buffer, offset + 4)?;
            Ok(RelocationEntry::Regular(RelocationInfo {
                r_address: Field::new(word0 as i32, offset, 4),
                r_symbolnum: Field::new(word1 & 0x00FF_FFFF, offset + 4, 4),
                r_pcrel: (word1 >> 24) & 1 != 0,
                r_length: ((word1 >> 25) & 0x03) as u8,
                r_extern: (word1 >> 27) & 1 != 0,
                r_type: ((word1 >> 28) & 0x0F) as u8,
            }))
        }
    }

    /// Parses `count` relocation entries starting at `offset`.
    pub fn parse_table(
        buffer: &[u8],
        offset: usize,
        count: usize,
        order: ByteOrder,
    ) -> Result<Vec<Self>, FileParseError> {
        let end = offset
            .checked_add(count * Self::SIZE)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }
        (0..count)
            .map(|i| Self::parse(buffer, offset + i * Self::SIZE, order))
            .collect()
    }
}
