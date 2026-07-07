//! COFF symbol table (`IMAGE_SYMBOL`) and string table.

use crate::errors::FileParseError;
use crate::field::{Field, FixedBytes};
use crate::utils::{extract_u16, extract_u32};

/// `IMAGE_SYMBOL` — 18 bytes in the COFF symbol table.
pub struct ImageSymbol {
    /// Short name bytes or `{ zeroes, string_table_offset }`.
    pub short_name: Field<FixedBytes<8>>,
    /// Symbol value (`Value`).
    pub value: Field<u32>,
    /// One-based section index (`SectionNumber`).
    pub section_number: Field<i16>,
    /// Symbol type (`Type`).
    pub sym_type: Field<u16>,
    /// Storage class (`StorageClass`).
    pub storage_class: Field<u8>,
    /// Number of auxiliary symbol records following this entry.
    pub number_of_aux_symbols: Field<u8>,
}

/// Resolved symbol name and on-disk record.
pub struct CoffSymbol {
    /// On-disk symbol fields.
    pub symbol: ImageSymbol,
    /// Absolute file offset of this `IMAGE_SYMBOL`.
    pub offset: usize,
    /// Decoded symbol name.
    pub name: String,
}

/// COFF symbol table plus string table.
pub struct CoffSymbolTable {
    /// Absolute file offset of the first `IMAGE_SYMBOL`.
    pub offset: usize,
    /// Absolute file offset of the COFF string table length prefix.
    pub string_table_offset: usize,
    /// Parsed symbols (auxiliary records are skipped).
    pub symbols: Vec<CoffSymbol>,
}

impl ImageSymbol {
    /// Size of `IMAGE_SYMBOL` in bytes.
    pub const SIZE: usize = 18;

    /// Parses one symbol at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        let short_name = FixedBytes::from_slice(&buffer[offset..offset + 8]);
        let section_raw = extract_u16(buffer, offset + 12)? as i16;

        Ok(ImageSymbol {
            short_name: Field::new(short_name, offset, 8),
            value: Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4),
            section_number: Field::new(section_raw, offset + 12, 2),
            number_of_aux_symbols: Field::new(
                buffer
                    .get(offset + 17)
                    .copied()
                    .ok_or(FileParseError::BufferOverflow)?,
                offset + 17,
                1,
            ),
            storage_class: Field::new(
                buffer
                    .get(offset + 16)
                    .copied()
                    .ok_or(FileParseError::BufferOverflow)?,
                offset + 16,
                1,
            ),
            sym_type: Field::new(extract_u16(buffer, offset + 14)?, offset + 14, 2),
        })
    }

    /// Resolves the symbol name using the COFF string table at `string_table_offset`.
    pub fn resolve_name(
        &self,
        buffer: &[u8],
        string_table_offset: usize,
    ) -> Result<String, FileParseError> {
        let bytes = &self.short_name.value.0;
        let zeroes = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if zeroes == 0 {
            let str_off = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
            let name_off = string_table_offset
                .checked_add(4)
                .and_then(|base| base.checked_add(str_off))
                .ok_or(FileParseError::BufferOverflow)?;
            return read_c_string(buffer, name_off);
        }

        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }
}

impl CoffSymbolTable {
    /// Parses the COFF symbol table referenced by the file header.
    pub fn parse(
        buffer: &[u8],
        symbol_table_offset: u32,
        number_of_symbols: u32,
    ) -> Result<Self, FileParseError> {
        if symbol_table_offset == 0 || number_of_symbols == 0 {
            return Ok(CoffSymbolTable {
                offset: 0,
                string_table_offset: 0,
                symbols: Vec::new(),
            });
        }

        let offset = symbol_table_offset as usize;
        let table_bytes = number_of_symbols as usize * ImageSymbol::SIZE;
        let end = offset
            .checked_add(table_bytes)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let string_table_offset = end;
        let mut symbols = Vec::new();
        let mut cursor = offset;
        let mut remaining = number_of_symbols;

        while remaining > 0 {
            let symbol = ImageSymbol::parse(buffer, cursor)?;
            let name = symbol.resolve_name(buffer, string_table_offset)?;
            let aux_count = symbol.number_of_aux_symbols.value as u32;
            symbols.push(CoffSymbol {
                symbol,
                offset: cursor,
                name,
            });
            cursor += ImageSymbol::SIZE;
            remaining -= 1;

            if aux_count > 0 {
                let skip = aux_count as usize * ImageSymbol::SIZE;
                cursor = cursor
                    .checked_add(skip)
                    .ok_or(FileParseError::BufferOverflow)?;
                remaining = remaining.saturating_sub(aux_count);
            }
        }

        Ok(CoffSymbolTable {
            offset,
            string_table_offset,
            symbols,
        })
    }
}

fn read_c_string(buffer: &[u8], offset: usize) -> Result<String, FileParseError> {
    let tail = buffer.get(offset..).ok_or(FileParseError::BufferOverflow)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(FileParseError::InvalidFileFormat)?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}
