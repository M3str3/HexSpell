//! Base relocation table parsing for PE images.
//!
//! The base relocation directory is a sequence of `IMAGE_BASE_RELOCATION`
//! blocks. Each block owns a page RVA and a list of 16-bit entries whose high
//! nibble is the relocation type and low 12 bits are the offset within the page.

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::header::PEType;
use crate::pe::import;
use crate::pe::section::PeSection;
use crate::utils::{extract_u16, extract_u32};

/// `IMAGE_REL_BASED_ABSOLUTE` padding entry.
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
/// `IMAGE_REL_BASED_HIGH`.
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
/// `IMAGE_REL_BASED_LOW`.
pub const IMAGE_REL_BASED_LOW: u16 = 2;
/// `IMAGE_REL_BASED_HIGHLOW`.
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
/// `IMAGE_REL_BASED_HIGHADJ`.
pub const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
/// `IMAGE_REL_BASED_DIR64`.
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

/// One 16-bit relocation entry inside an `IMAGE_BASE_RELOCATION` block.
pub struct BaseRelocationEntry {
    /// Raw relocation word (`type << 12 | offset`).
    pub raw: Field<u16>,
}

impl BaseRelocationEntry {
    /// Relocation type stored in the high 4 bits.
    pub fn relocation_type(&self) -> u16 {
        self.raw.value >> 12
    }

    /// Offset within the block page RVA stored in the low 12 bits.
    pub fn offset(&self) -> u16 {
        self.raw.value & 0x0fff
    }

    /// RVA of the item patched by this relocation entry.
    pub fn rva(&self, page_rva: u32) -> u32 {
        page_rva + self.offset() as u32
    }
}

/// `IMAGE_BASE_RELOCATION` block plus its decoded 16-bit entries.
pub struct BaseRelocationBlock {
    /// Page RVA covered by this block.
    pub page_rva: Field<u32>,
    /// Total block size in bytes, including this header.
    pub block_size: Field<u32>,
    /// Relocation entries immediately following the 8-byte block header.
    pub entries: Vec<BaseRelocationEntry>,
}

impl BaseRelocationBlock {
    /// Parses a single `IMAGE_BASE_RELOCATION` block at a file offset.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        let page_rva = extract_u32(buffer, offset)?;
        let block_size = extract_u32(buffer, offset + 4)?;

        if block_size < 8 || block_size % 2 != 0 {
            return Err(FileParseError::InvalidFileFormat);
        }

        let end = offset
            .checked_add(block_size as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let entry_count = (block_size as usize - 8) / 2;
        let mut entries = Vec::with_capacity(entry_count);
        let mut entry_offset = offset + 8;
        for _ in 0..entry_count {
            entries.push(BaseRelocationEntry {
                raw: Field::new(extract_u16(buffer, entry_offset)?, entry_offset, 2),
            });
            entry_offset += 2;
        }

        Ok(BaseRelocationBlock {
            page_rva: Field::new(page_rva, offset, 4),
            block_size: Field::new(block_size, offset + 4, 4),
            entries,
        })
    }
}

/// Parses the full base relocation directory.
pub fn parse_base_relocations(
    buffer: &[u8],
    offset: usize,
    size: usize,
) -> Result<Vec<BaseRelocationBlock>, FileParseError> {
    let end = offset
        .checked_add(size)
        .ok_or(FileParseError::BufferOverflow)?;
    if buffer.len() < end {
        return Err(FileParseError::BufferOverflow);
    }

    let mut blocks = Vec::new();
    let mut current = offset;
    while current < end {
        if end - current < 8 {
            return Err(FileParseError::InvalidFileFormat);
        }

        let block = BaseRelocationBlock::parse(buffer, current)?;
        let next = current
            .checked_add(block.block_size.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        if next > end {
            return Err(FileParseError::BufferOverflow);
        }

        blocks.push(block);
        current = next;
    }

    Ok(blocks)
}

/// Applies base relocations after changing the preferred image base.
///
/// Patches `buffer` in place for `IMAGE_REL_BASED_HIGHLOW` (PE32) and
/// `IMAGE_REL_BASED_DIR64` (PE32+) entries. Other relocation types are skipped.
pub fn apply_base_relocations(
    buffer: &mut [u8],
    blocks: &[BaseRelocationBlock],
    sections: &[PeSection],
    old_base: u64,
    new_base: u64,
    pe_type: PEType,
) -> Result<(), FileParseError> {
    let delta = i64::try_from(new_base)
        .and_then(|new| i64::try_from(old_base).map(|old| new - old))
        .map_err(|_| FileParseError::ValueTooLarge)?;

    if delta == 0 {
        return Ok(());
    }

    for block in blocks {
        for entry in &block.entries {
            let reloc_type = entry.relocation_type();
            if reloc_type == IMAGE_REL_BASED_ABSOLUTE {
                continue;
            }

            let rva = entry.rva(block.page_rva.value);
            let offset = import::rva_to_offset(buffer, sections, rva)?;

            match (pe_type, reloc_type) {
                (PEType::PE32, IMAGE_REL_BASED_HIGHLOW) => {
                    if buffer.len() < offset + 4 {
                        return Err(FileParseError::BufferOverflow);
                    }
                    let current = u32::from_le_bytes([
                        buffer[offset],
                        buffer[offset + 1],
                        buffer[offset + 2],
                        buffer[offset + 3],
                    ]);
                    let patched = (current as i64 + delta) as u32;
                    buffer[offset..offset + 4].copy_from_slice(&patched.to_le_bytes());
                }
                (PEType::PE32Plus, IMAGE_REL_BASED_DIR64) => {
                    if buffer.len() < offset + 8 {
                        return Err(FileParseError::BufferOverflow);
                    }
                    let current = u64::from_le_bytes([
                        buffer[offset],
                        buffer[offset + 1],
                        buffer[offset + 2],
                        buffer[offset + 3],
                        buffer[offset + 4],
                        buffer[offset + 5],
                        buffer[offset + 6],
                        buffer[offset + 7],
                    ]);
                    let patched = (current as i64 + delta) as u64;
                    buffer[offset..offset + 8].copy_from_slice(&patched.to_le_bytes());
                }
                _ => {}
            }
        }
    }

    Ok(())
}
