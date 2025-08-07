//! Parsing utilities for ELF program headers.
//!
//! Program headers describe how each segment of the binary is to be
//! loaded into memory. The functions here iterate over the header table,
//! honoring the file's endianness and returning high level
//! [`ProgramHeader`] values that expose offsets, permissions and sizes.
//! These structures can then be patched and written back using `Field`
//! semantics.

use super::header::Endianness;
use crate::errors;
use crate::field::Field;

#[derive(Debug)]
pub struct ProgramHeader {
    pub p_type: Field<u32>,
    pub p_flags: Field<u32>,
    pub p_offset: Field<u64>,
    pub p_vaddr: Field<u64>,
    pub p_paddr: Field<u64>,
    pub p_filesz: Field<u64>,
    pub p_memsz: Field<u64>,
    pub p_align: Field<u64>,
}

impl ProgramHeader {
    pub fn parse_program_headers(
        buffer: &[u8],
        offset: u64,
        size: u16,
        count: u16,
        endianness: Endianness,
    ) -> Result<Vec<ProgramHeader>, errors::FileParseError> {
        let mut headers = Vec::new();
        let start = offset as usize;

        for i in 0..count as usize {
            let base = start + i * size as usize;
            if buffer.len() < base + size as usize {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let read_u32 = |slice: &[u8]| -> Result<u32, errors::FileParseError> {
                let arr: [u8; 4] = slice
                    .try_into()
                    .map_err(|_| errors::FileParseError::BufferOverflow)?;
                Ok(match endianness {
                    Endianness::Little => u32::from_le_bytes(arr),
                    Endianness::Big => u32::from_be_bytes(arr),
                })
            };
            let read_u64 = |slice: &[u8]| -> Result<u64, errors::FileParseError> {
                let arr: [u8; 8] = slice
                    .try_into()
                    .map_err(|_| errors::FileParseError::BufferOverflow)?;
                Ok(match endianness {
                    Endianness::Little => u64::from_le_bytes(arr),
                    Endianness::Big => u64::from_be_bytes(arr),
                })
            };

            let p_type: Field<u32> = Field::new(read_u32(&buffer[base..base + 4])?, base, 4);
            let p_flags: Field<u32> =
                Field::new(read_u32(&buffer[base + 4..base + 8])?, base + 4, 4);
            let p_offset: Field<u64> =
                Field::new(read_u64(&buffer[base + 8..base + 16])?, base + 8, 8);
            let p_vaddr: Field<u64> =
                Field::new(read_u64(&buffer[base + 16..base + 24])?, base + 16, 8);
            let p_paddr: Field<u64> =
                Field::new(read_u64(&buffer[base + 24..base + 32])?, base + 24, 8);
            let p_filesz: Field<u64> =
                Field::new(read_u64(&buffer[base + 32..base + 40])?, base + 32, 8);
            let p_memsz: Field<u64> =
                Field::new(read_u64(&buffer[base + 40..base + 48])?, base + 40, 8);
            let p_align: Field<u64> =
                Field::new(read_u64(&buffer[base + 48..base + 56])?, base + 48, 8);

            headers.push(ProgramHeader {
                p_type,
                p_flags,
                p_offset,
                p_vaddr,
                p_paddr,
                p_filesz,
                p_memsz,
                p_align,
            });
        }

        Ok(headers)
    }
}
