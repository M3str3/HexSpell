//! Dyld bind/export blob decoding (`LC_DYLD_INFO`, `LC_DYLD_EXPORTS_TRIE`).
//!
//! These routines walk the compressed opcode streams described in Apple's dyld sources. They expose
//! decoded records for inspection; they do not apply relocations or resolve symbols at runtime.

use crate::errors::FileParseError;

/// `BIND_OPCODE_*` immediate values for [`BindOpcode::SetDylibOrdinalImm`].
pub mod bind_imm {
    /// Self (main executable).
    pub const SELF: i8 = -1;
    /// Flat lookup (all symbols).
    pub const FLAT_LOOKUP: i8 = -2;
    /// Weak lookup.
    pub const WEAK_LOOKUP: i8 = -3;
}

/// One decoded bind opcode from a bind / lazy-bind / weak-bind stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOpcode {
    /// `BIND_OPCODE_DONE` (0x00).
    Done,
    /// `BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB` (0x10).
    SetDylibOrdinalUleb(u64),
    /// `BIND_OPCODE_SET_DYLIB_ORDINAL_IMM` (0x40 | imm).
    SetDylibOrdinalImm(i8),
    /// `BIND_OPCODE_SET_DYLIB_SPECIAL_IMM` (0x30 | imm).
    SetDylibSpecialImm(i8),
    /// `BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM` (0x50 | flags).
    SetSymbolTrailingFlagsImm(u8),
    /// `BIND_OPCODE_SET_TYPE_IMM` (0x70 | type).
    SetTypeImm(u8),
    /// `BIND_OPCODE_SET_ADDEND_SLEB` (0x80).
    SetAddendSleb(i64),
    /// `BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB` (0x90).
    SetSegmentAndOffsetUleb {
        /// Segment index (0-based).
        segment: u64,
        /// Offset within the segment.
        offset: u64,
    },
    /// `BIND_OPCODE_ADD_ADDR_ULEB` (0xA0).
    AddAddrUleb(u64),
    /// `BIND_OPCODE_DO_BIND` (0xB0).
    DoBind,
    /// `BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB` (0xC0).
    DoBindAddAddrUleb(u64),
    /// `BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED` (0xD0 | scale).
    DoBindAddAddrImmScaled(u8),
    /// `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB` (0xE0).
    DoBindUlebTimesSkippingUleb {
        /// Number of bind operations.
        count: u64,
        /// Bytes to skip after each bind.
        skip: u64,
    },
    /// Unrecognized opcode byte.
    Unknown(u8),
}

/// One exported symbol decoded from an export trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportTrieEntry {
    /// Full exported name (path through the trie).
    pub name: String,
    /// Export flags (`EXPORT_SYMBOL_FLAGS_*`).
    pub flags: u64,
    /// In-image address (when not a re-export).
    pub address: Option<u64>,
    /// Re-export dylib ordinal (when `flags` indicates re-export).
    pub reexport_dylib: Option<u64>,
    /// Re-exported symbol name (when `flags` indicates re-export).
    pub reexport_name: Option<String>,
    /// Stub resolver offset (when `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER` is set).
    pub resolver: Option<u64>,
}

const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

/// Decodes a bind / lazy-bind / weak-bind opcode stream.
pub fn decode_bind_opcodes(data: &[u8]) -> Result<Vec<BindOpcode>, FileParseError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let byte = data[pos];
        pos += 1;
        let op = match byte {
            0x00 => BindOpcode::Done,
            0x10 => {
                let (v, n) = read_uleb128(data, pos)?;
                pos += n;
                BindOpcode::SetDylibOrdinalUleb(v)
            }
            b if (b & 0xF0) == 0x40 => BindOpcode::SetDylibOrdinalImm((b & 0x0F) as i8),
            b if (b & 0xF0) == 0x30 => BindOpcode::SetDylibSpecialImm(-((b & 0x0F) as i8)),
            b if (b & 0xF0) == 0x50 => BindOpcode::SetSymbolTrailingFlagsImm(b & 0x0F),
            b if (b & 0xF0) == 0x70 => BindOpcode::SetTypeImm(b & 0x0F),
            0x80 => {
                let (v, n) = read_sleb128(data, pos)?;
                pos += n;
                BindOpcode::SetAddendSleb(v)
            }
            0x90 => {
                let (seg, n1) = read_uleb128(data, pos)?;
                pos += n1;
                let (off, n2) = read_uleb128(data, pos)?;
                pos += n2;
                BindOpcode::SetSegmentAndOffsetUleb {
                    segment: seg,
                    offset: off,
                }
            }
            0xA0 => {
                let (v, n) = read_uleb128(data, pos)?;
                pos += n;
                BindOpcode::AddAddrUleb(v)
            }
            0xB0 => BindOpcode::DoBind,
            0xC0 => {
                let (v, n) = read_uleb128(data, pos)?;
                pos += n;
                BindOpcode::DoBindAddAddrUleb(v)
            }
            b if (b & 0xF0) == 0xD0 => BindOpcode::DoBindAddAddrImmScaled(b & 0x0F),
            0xE0 => {
                let (count, n1) = read_uleb128(data, pos)?;
                pos += n1;
                let (skip, n2) = read_uleb128(data, pos)?;
                pos += n2;
                BindOpcode::DoBindUlebTimesSkippingUleb { count, skip }
            }
            other => BindOpcode::Unknown(other),
        };
        out.push(op);
        if matches!(out.last(), Some(BindOpcode::Done)) {
            break;
        }
    }
    Ok(out)
}

/// Decodes every exported symbol from an export trie blob.
pub fn decode_export_trie(data: &[u8]) -> Result<Vec<ExportTrieEntry>, FileParseError> {
    let mut out = Vec::new();
    walk_export_node(data, 0, String::new(), &mut out)?;
    Ok(out)
}

fn walk_export_node(
    data: &[u8],
    node_offset: usize,
    prefix: String,
    out: &mut Vec<ExportTrieEntry>,
) -> Result<(), FileParseError> {
    if node_offset >= data.len() {
        return Ok(());
    }

    let mut pos = node_offset;
    let terminal_size = if data[pos] & 0x80 != 0 {
        let (v, n) = read_uleb128(data, pos)?;
        pos += n;
        v as usize
    } else {
        let v = data[pos] as usize;
        pos += 1;
        v
    };

    if terminal_size > 0 {
        let term_end = pos
            .checked_add(terminal_size)
            .ok_or(FileParseError::BufferOverflow)?;
        if term_end > data.len() {
            return Err(FileParseError::BufferOverflow);
        }
        let term = &data[pos..term_end];
        pos = term_end;
        if let Some(entry) = parse_terminal_export(prefix.clone(), term)? {
            out.push(entry);
        }
    }

    if pos >= data.len() {
        return Ok(());
    }

    let child_count = data[pos] as usize;
    pos += 1;
    for _ in 0..child_count {
        if pos >= data.len() {
            return Err(FileParseError::BufferOverflow);
        }
        let edge = data[pos] as char;
        pos += 1;
        let (child_off, n) = read_uleb128(data, pos)?;
        pos += n;
        let mut child_prefix = prefix.clone();
        child_prefix.push(edge);
        walk_export_node(data, child_off as usize, child_prefix, out)?;
    }

    Ok(())
}

fn parse_terminal_export(
    name: String,
    term: &[u8],
) -> Result<Option<ExportTrieEntry>, FileParseError> {
    if term.is_empty() {
        return Ok(None);
    }
    let (flags, n1) = read_uleb128(term, 0)?;
    let mut pos = n1;

    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let (dylib, n2) = read_uleb128(term, pos)?;
        pos += n2;
        let reexport_name = read_cstring(term, pos)?;
        return Ok(Some(ExportTrieEntry {
            name,
            flags,
            address: None,
            reexport_dylib: Some(dylib),
            reexport_name: Some(reexport_name),
            resolver: None,
        }));
    }

    let (address, n3) = read_uleb128(term, pos)?;
    pos += n3;
    let resolver = if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        let (r, n4) = read_uleb128(term, pos)?;
        pos += n4;
        Some(r)
    } else {
        None
    };
    let _ = pos;

    Ok(Some(ExportTrieEntry {
        name,
        flags,
        address: Some(address),
        reexport_dylib: None,
        reexport_name: None,
        resolver,
    }))
}

fn read_cstring(data: &[u8], offset: usize) -> Result<String, FileParseError> {
    let slice = data.get(offset..).ok_or(FileParseError::BufferOverflow)?;
    let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..stop]).into_owned())
}

fn read_uleb128(data: &[u8], mut offset: usize) -> Result<(u64, usize), FileParseError> {
    let start = offset;
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(offset).ok_or(FileParseError::BufferOverflow)?;
        offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(FileParseError::InvalidFileFormat);
        }
    }
    Ok((result, offset - start))
}

fn read_sleb128(data: &[u8], mut offset: usize) -> Result<(i64, usize), FileParseError> {
    let start = offset;
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut byte;
    loop {
        byte = *data.get(offset).ok_or(FileParseError::BufferOverflow)?;
        offset += 1;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err(FileParseError::InvalidFileFormat);
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok((result, offset - start))
}
