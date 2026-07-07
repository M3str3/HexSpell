//! Rich header (linker tool metadata between the DOS stub and PE signature).

use crate::errors::FileParseError;
use crate::utils::extract_u32;

/// `DanS` signature (`0x536e6144`).
const DANS_MAGIC: u32 = 0x536e_6144;
/// `Rich` signature (`0x68636952`).
const RICH_MAGIC: u32 = 0x6863_6952;

/// One `(product_id, build_id)` pair and its occurrence count from the Rich header.
pub struct RichEntry {
    /// Tool product id (high 16 bits of the decoded tool dword).
    pub product_id: u16,
    /// Tool build id (low 16 bits of the decoded tool dword).
    pub build_id: u16,
    /// Number of times this tool appears in the link chain.
    pub count: u32,
}

/// Parsed Rich header.
pub struct RichHeader {
    /// Absolute file offset of the encrypted `DanS` dword.
    pub offset: usize,
    /// XOR key used to encrypt Rich header dwords.
    pub xor_key: u32,
    /// Decoded tool entries in file order.
    pub entries: Vec<RichEntry>,
}

impl RichHeader {
    /// Parses the Rich header in `buffer` when present between the DOS stub and `pe_offset`.
    ///
    /// Returns `Ok(None)` when no Rich header is found.
    pub fn parse(buffer: &[u8], pe_offset: usize) -> Result<Option<Self>, FileParseError> {
        if pe_offset < 0x80 + 16 || buffer.len() < 0x80 + 16 {
            return Ok(None);
        }

        let start = 0x80usize;
        let encrypted_dans = extract_u32(buffer, start)?;
        let xor_key = encrypted_dans ^ DANS_MAGIC;
        if encrypted_dans ^ xor_key != DANS_MAGIC {
            return Ok(None);
        }

        let mut entries = Vec::new();
        let mut cursor = start + 4;
        let end = pe_offset.saturating_sub(8);

        while cursor + 8 <= end {
            let tool = extract_u32(buffer, cursor)? ^ xor_key;
            let count = extract_u32(buffer, cursor + 4)? ^ xor_key;

            if tool == RICH_MAGIC {
                break;
            }

            entries.push(RichEntry {
                product_id: (tool >> 16) as u16,
                build_id: tool as u16,
                count,
            });
            cursor += 8;
        }

        if entries.is_empty() {
            return Ok(None);
        }

        Ok(Some(RichHeader {
            offset: start,
            xor_key,
            entries,
        }))
    }
}
