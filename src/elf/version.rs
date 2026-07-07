//! GNU ELF symbol version sections.

use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// One `Elf*_Versym` entry from `.gnu.version`.
pub struct VersionSymbol {
    /// Version index for one dynamic symbol.
    pub ndx: Field<u16>,
}

/// Parsed `.gnu.version` table.
pub struct VersionSymbolTable {
    /// Version entries in dynamic-symbol order.
    pub entries: Vec<VersionSymbol>,
}

impl VersionSymbolTable {
    /// Parses `.gnu.version` entries.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: usize,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        let mut entries = Vec::with_capacity(size / 2);
        let mut cursor = offset;
        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        while cursor + 2 <= end {
            entries.push(VersionSymbol {
                ndx: Field::new(order.read_u16(buffer, cursor)?, cursor, 2),
            });
            cursor += 2;
        }
        Ok(Self { entries })
    }
}

/// `Elf*_Verneed` header from `.gnu.version_r`.
pub struct VersionNeed {
    pub vn_version: Field<u16>,
    pub vn_cnt: Field<u16>,
    pub vn_file: Field<u32>,
    pub vn_aux: Field<u32>,
    pub vn_next: Field<u32>,
    pub aux: Vec<VersionNeedAux>,
}

/// `Elf*_Vernaux` entry from `.gnu.version_r`.
pub struct VersionNeedAux {
    pub vna_hash: Field<u32>,
    pub vna_flags: Field<u16>,
    pub vna_other: Field<u16>,
    pub vna_name: Field<u32>,
    pub vna_next: Field<u32>,
}

/// Parsed `.gnu.version_r` section.
pub struct VersionNeedTable {
    pub entries: Vec<VersionNeed>,
}

impl VersionNeedTable {
    /// Parses required version records.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: usize,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        let mut entries = Vec::new();
        let mut base = offset;
        while base + 16 <= end {
            let vn_cnt = Field::new(order.read_u16(buffer, base + 2)?, base + 2, 2);
            let vn_aux = Field::new(order.read_u32(buffer, base + 8)?, base + 8, 4);
            let vn_next = Field::new(order.read_u32(buffer, base + 12)?, base + 12, 4);
            let mut aux = Vec::with_capacity(vn_cnt.value as usize);
            let mut aux_base = base + vn_aux.value as usize;
            for _ in 0..vn_cnt.value {
                if aux_base + 16 > end {
                    return Err(FileParseError::BufferOverflow);
                }
                let vna_next = Field::new(order.read_u32(buffer, aux_base + 12)?, aux_base + 12, 4);
                aux.push(VersionNeedAux {
                    vna_hash: Field::new(order.read_u32(buffer, aux_base)?, aux_base, 4),
                    vna_flags: Field::new(order.read_u16(buffer, aux_base + 4)?, aux_base + 4, 2),
                    vna_other: Field::new(order.read_u16(buffer, aux_base + 6)?, aux_base + 6, 2),
                    vna_name: Field::new(order.read_u32(buffer, aux_base + 8)?, aux_base + 8, 4),
                    vna_next: vna_next.clone(),
                });
                if vna_next.value == 0 {
                    break;
                }
                aux_base += vna_next.value as usize;
            }
            entries.push(VersionNeed {
                vn_version: Field::new(order.read_u16(buffer, base)?, base, 2),
                vn_cnt,
                vn_file: Field::new(order.read_u32(buffer, base + 4)?, base + 4, 4),
                vn_aux,
                vn_next: vn_next.clone(),
                aux,
            });
            if vn_next.value == 0 {
                break;
            }
            base += vn_next.value as usize;
        }
        Ok(Self { entries })
    }
}

/// `Elf*_Verdef` header from `.gnu.version_d`.
pub struct VersionDef {
    pub vd_version: Field<u16>,
    pub vd_flags: Field<u16>,
    pub vd_ndx: Field<u16>,
    pub vd_cnt: Field<u16>,
    pub vd_hash: Field<u32>,
    pub vd_aux: Field<u32>,
    pub vd_next: Field<u32>,
}

/// Parsed `.gnu.version_d` section.
pub struct VersionDefTable {
    pub entries: Vec<VersionDef>,
}

impl VersionDefTable {
    /// Parses version definition records.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: usize,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        let mut entries = Vec::new();
        let mut base = offset;
        while base + 20 <= end {
            let vd_next = Field::new(order.read_u32(buffer, base + 16)?, base + 16, 4);
            entries.push(VersionDef {
                vd_version: Field::new(order.read_u16(buffer, base)?, base, 2),
                vd_flags: Field::new(order.read_u16(buffer, base + 2)?, base + 2, 2),
                vd_ndx: Field::new(order.read_u16(buffer, base + 4)?, base + 4, 2),
                vd_cnt: Field::new(order.read_u16(buffer, base + 6)?, base + 6, 2),
                vd_hash: Field::new(order.read_u32(buffer, base + 8)?, base + 8, 4),
                vd_aux: Field::new(order.read_u32(buffer, base + 12)?, base + 12, 4),
                vd_next: vd_next.clone(),
            });
            if vd_next.value == 0 {
                break;
            }
            base += vd_next.value as usize;
        }
        Ok(Self { entries })
    }
}
