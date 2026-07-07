//! Mach-O symbol table (`nlist` / `nlist_64`) parsing and name resolution.
//!
//! The table is located through [`LC_SYMTAB`](super::load_command::LC_SYMTAB): `symoff`/`nsyms`
//! locate the `nlist` array and `stroff`/`strsize` the string pool that `n_strx` indexes into.

use super::load_command::SymtabCommand;
use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// `N_STAB` mask — entry is a debugging (stabs) symbol.
pub const N_STAB: u8 = 0xe0;
/// `N_TYPE` mask — the symbol type bits of `n_type`.
pub const N_TYPE: u8 = 0x0e;
/// `N_EXT` mask — external symbol bit of `n_type`.
pub const N_EXT: u8 = 0x01;
/// `N_UNDF` — undefined symbol (`N_TYPE`).
pub const N_UNDF: u8 = 0x0;
/// `N_SECT` — symbol defined in the section `n_sect` (`N_TYPE`).
pub const N_SECT: u8 = 0xe;

/// One `nlist` / `nlist_64` record plus its resolved name.
#[derive(Debug)]
pub struct Nlist {
    /// String table index of the name (`n_strx`).
    pub n_strx: Field<u32>,
    /// Symbol type flags (`n_type`).
    pub n_type: Field<u8>,
    /// Section index (`n_sect`), one-based, or `0`.
    pub n_sect: Field<u8>,
    /// Description flags (`n_desc`).
    pub n_desc: Field<u16>,
    /// Symbol value / address (`n_value`).
    pub n_value: Field<u64>,
    /// Resolved symbol name.
    pub name: String,
}

impl Nlist {
    /// `true` when this is a debugging (stabs) entry.
    pub fn is_stab(&self) -> bool {
        self.n_type.value & N_STAB != 0
    }

    /// `true` when the external bit is set.
    pub fn is_external(&self) -> bool {
        self.n_type.value & N_EXT != 0
    }

    /// `true` when the symbol is undefined (imported).
    pub fn is_undefined(&self) -> bool {
        !self.is_stab() && (self.n_type.value & N_TYPE) == N_UNDF
    }
}

/// Parsed Mach-O symbol table (`nlist` array + string pool).
#[derive(Debug)]
pub struct SymbolTable {
    /// File offset of the `nlist` array.
    pub offset: usize,
    /// File offset of the string table.
    pub string_table_offset: usize,
    /// Parsed symbols in file order.
    pub symbols: Vec<Nlist>,
}

impl SymbolTable {
    /// Parses the symbol table described by an `LC_SYMTAB` command.
    pub fn parse(
        buffer: &[u8],
        symtab: &SymtabCommand,
        is_64: bool,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        let symoff = symtab.symoff.value as usize;
        let nsyms = symtab.nsyms.value as usize;
        let stroff = symtab.stroff.value as usize;
        let strsize = symtab.strsize.value as usize;
        let entry_size = if is_64 { 16 } else { 12 };

        let str_end = stroff
            .checked_add(strsize)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < str_end {
            return Err(FileParseError::BufferOverflow);
        }

        let mut symbols = Vec::with_capacity(nsyms);
        for i in 0..nsyms {
            let off = symoff
                .checked_add(i * entry_size)
                .ok_or(FileParseError::BufferOverflow)?;
            if buffer.len() < off + entry_size {
                return Err(FileParseError::BufferOverflow);
            }

            let n_strx = order.read_u32(buffer, off)?;
            let n_type = buffer[off + 4];
            let n_sect = buffer[off + 5];
            let n_desc = order.read_u16(buffer, off + 6)?;
            let n_value = if is_64 {
                order.read_u64(buffer, off + 8)?
            } else {
                order.read_u32(buffer, off + 8)? as u64
            };
            let value_size = if is_64 { 8 } else { 4 };

            let name = resolve_name(buffer, stroff, strsize, n_strx as usize)?;

            symbols.push(Nlist {
                n_strx: Field::new(n_strx, off, 4),
                n_type: Field::new(n_type, off + 4, 1),
                n_sect: Field::new(n_sect, off + 5, 1),
                n_desc: Field::new(n_desc, off + 6, 2),
                n_value: Field::new(n_value, off + 8, value_size),
                name,
            });
        }

        Ok(SymbolTable {
            offset: symoff,
            string_table_offset: stroff,
            symbols,
        })
    }
}

/// Resolves a symbol name from the string pool. Index `0` denotes an empty name.
fn resolve_name(
    buffer: &[u8],
    stroff: usize,
    strsize: usize,
    n_strx: usize,
) -> Result<String, FileParseError> {
    if n_strx == 0 || n_strx >= strsize {
        return Ok(String::new());
    }
    let start = stroff + n_strx;
    let end = stroff + strsize;
    let slice = buffer
        .get(start..end)
        .ok_or(FileParseError::BufferOverflow)?;
    let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..stop]).into_owned())
}
