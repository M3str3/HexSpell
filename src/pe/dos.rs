//! DOS header (`IMAGE_DOS_HEADER`) — 64 bytes, little-endian.

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

/// DOS header (`IMAGE_DOS_HEADER`) — 64 bytes, little-endian.
///
/// All fields map 1:1 to the specification. [`DosHeader::e_lfanew`] points to the `PE\0\0` signature.
#[derive(Debug)]
pub struct DosHeader {
    /// `e_magic` — must be `0x5A4D` (`"MZ"`).
    pub e_magic: Field<u16>,
    pub e_cblp: Field<u16>,
    pub e_cp: Field<u16>,
    pub e_crlc: Field<u16>,
    pub e_cparhdr: Field<u16>,
    pub e_minalloc: Field<u16>,
    pub e_maxalloc: Field<u16>,
    pub e_ss: Field<u16>,
    pub e_sp: Field<u16>,
    pub e_csum: Field<u16>,
    pub e_ip: Field<u16>,
    pub e_cs: Field<u16>,
    pub e_lfarlc: Field<u16>,
    pub e_ovno: Field<u16>,
    pub e_res0: Field<u16>,
    pub e_res1: Field<u16>,
    pub e_res2: Field<u16>,
    pub e_res3: Field<u16>,
    pub e_oemid: Field<u16>,
    pub e_oeminfo: Field<u16>,
    pub e_res2_0: Field<u16>,
    pub e_res2_1: Field<u16>,
    pub e_res2_2: Field<u16>,
    pub e_res2_3: Field<u16>,
    pub e_res2_4: Field<u16>,
    pub e_res2_5: Field<u16>,
    pub e_res2_6: Field<u16>,
    pub e_res2_7: Field<u16>,
    pub e_res2_8: Field<u16>,
    pub e_res2_9: Field<u16>,
    /// File offset of the PE signature (`PE\0\0`).
    pub e_lfanew: Field<u32>,
}

impl DosHeader {
    /// Parses the DOS header at the start of `buffer`.
    pub fn parse(buffer: &[u8]) -> Result<Self, FileParseError> {
        if buffer.len() < 64 {
            return Err(FileParseError::BufferOverflow);
        }
        let e_magic = extract_u16(buffer, 0)?;
        if e_magic != 0x5A4D {
            return Err(FileParseError::InvalidFileFormat);
        }

        Ok(DosHeader {
            e_magic: Field::new(e_magic, 0, 2),
            e_cblp: Field::new(extract_u16(buffer, 2)?, 2, 2),
            e_cp: Field::new(extract_u16(buffer, 4)?, 4, 2),
            e_crlc: Field::new(extract_u16(buffer, 6)?, 6, 2),
            e_cparhdr: Field::new(extract_u16(buffer, 8)?, 8, 2),
            e_minalloc: Field::new(extract_u16(buffer, 10)?, 10, 2),
            e_maxalloc: Field::new(extract_u16(buffer, 12)?, 12, 2),
            e_ss: Field::new(extract_u16(buffer, 14)?, 14, 2),
            e_sp: Field::new(extract_u16(buffer, 16)?, 16, 2),
            e_csum: Field::new(extract_u16(buffer, 18)?, 18, 2),
            e_ip: Field::new(extract_u16(buffer, 20)?, 20, 2),
            e_cs: Field::new(extract_u16(buffer, 22)?, 22, 2),
            e_lfarlc: Field::new(extract_u16(buffer, 24)?, 24, 2),
            e_ovno: Field::new(extract_u16(buffer, 26)?, 26, 2),
            e_res0: Field::new(extract_u16(buffer, 28)?, 28, 2),
            e_res1: Field::new(extract_u16(buffer, 30)?, 30, 2),
            e_res2: Field::new(extract_u16(buffer, 32)?, 32, 2),
            e_res3: Field::new(extract_u16(buffer, 34)?, 34, 2),
            e_oemid: Field::new(extract_u16(buffer, 36)?, 36, 2),
            e_oeminfo: Field::new(extract_u16(buffer, 38)?, 38, 2),
            e_res2_0: Field::new(extract_u16(buffer, 40)?, 40, 2),
            e_res2_1: Field::new(extract_u16(buffer, 42)?, 42, 2),
            e_res2_2: Field::new(extract_u16(buffer, 44)?, 44, 2),
            e_res2_3: Field::new(extract_u16(buffer, 46)?, 46, 2),
            e_res2_4: Field::new(extract_u16(buffer, 48)?, 48, 2),
            e_res2_5: Field::new(extract_u16(buffer, 50)?, 50, 2),
            e_res2_6: Field::new(extract_u16(buffer, 52)?, 52, 2),
            e_res2_7: Field::new(extract_u16(buffer, 54)?, 54, 2),
            e_res2_8: Field::new(extract_u16(buffer, 56)?, 56, 2),
            e_res2_9: Field::new(extract_u16(buffer, 58)?, 58, 2),
            e_lfanew: Field::new(extract_u32(buffer, 60)?, 60, 4),
        })
    }
}
