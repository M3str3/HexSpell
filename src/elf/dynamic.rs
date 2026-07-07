//! ELF dynamic linking table (`.dynamic`).
//!
//! The dynamic section is an array of `(d_tag, d_val/d_ptr)` pairs. [`DynamicEntry`] exposes both
//! members as [`Field`] values with their real file offsets. Parsing stops at the `DT_NULL`
//! terminator. Common tags are available as `DT_*` constants and via [`DynamicEntry::tag_kind`].

use super::header::ElfClass;
use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field, NumericFieldMut};

/// `DT_NULL` — marks the end of the dynamic array.
pub const DT_NULL: u64 = 0;
/// `DT_NEEDED` — string table offset of a needed library name.
pub const DT_NEEDED: u64 = 1;
/// `DT_PLTRELSZ` — total size of the PLT relocation entries.
pub const DT_PLTRELSZ: u64 = 2;
/// `DT_PLTGOT` — address of the PLT/GOT.
pub const DT_PLTGOT: u64 = 3;
/// `DT_HASH` — address of the symbol hash table.
pub const DT_HASH: u64 = 4;
/// `DT_STRTAB` — address of the dynamic string table.
pub const DT_STRTAB: u64 = 5;
/// `DT_SYMTAB` — address of the dynamic symbol table.
pub const DT_SYMTAB: u64 = 6;
/// `DT_RELA` — address of a relocation table with addends.
pub const DT_RELA: u64 = 7;
/// `DT_RELASZ` — total size of the `DT_RELA` table.
pub const DT_RELASZ: u64 = 8;
/// `DT_RELAENT` — size of a `DT_RELA` entry.
pub const DT_RELAENT: u64 = 9;
/// `DT_STRSZ` — size of the dynamic string table.
pub const DT_STRSZ: u64 = 10;
/// `DT_SYMENT` — size of a dynamic symbol entry.
pub const DT_SYMENT: u64 = 11;
/// `DT_INIT` — address of the initialization function.
pub const DT_INIT: u64 = 12;
/// `DT_FINI` — address of the termination function.
pub const DT_FINI: u64 = 13;
/// `DT_SONAME` — string table offset of the shared object name.
pub const DT_SONAME: u64 = 14;
/// `DT_RPATH` — string table offset of a library search path.
pub const DT_RPATH: u64 = 15;
/// `DT_SYMBOLIC` — alters symbol resolution order.
pub const DT_SYMBOLIC: u64 = 16;
/// `DT_REL` — address of a relocation table without addends.
pub const DT_REL: u64 = 17;
/// `DT_RELSZ` — total size of the `DT_REL` table.
pub const DT_RELSZ: u64 = 18;
/// `DT_RELENT` — size of a `DT_REL` entry.
pub const DT_RELENT: u64 = 19;
/// `DT_PLTREL` — relocation type used by the PLT (`DT_REL` or `DT_RELA`).
pub const DT_PLTREL: u64 = 20;
/// `DT_DEBUG` — used for debugging.
pub const DT_DEBUG: u64 = 21;
/// `DT_TEXTREL` — relocations may modify a non-writable segment.
pub const DT_TEXTREL: u64 = 22;
/// `DT_JMPREL` — address of the PLT relocation entries.
pub const DT_JMPREL: u64 = 23;
/// `DT_RUNPATH` — string table offset of a library search path.
pub const DT_RUNPATH: u64 = 29;
/// `DT_FLAGS` — dynamic flags.
pub const DT_FLAGS: u64 = 30;

/// Typed view of a dynamic tag for the common entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicTag {
    Null,
    Needed,
    PltRelSz,
    PltGot,
    Hash,
    StrTab,
    SymTab,
    Rela,
    RelaSz,
    RelaEnt,
    StrSz,
    SymEnt,
    Init,
    Fini,
    SoName,
    RPath,
    Symbolic,
    Rel,
    RelSz,
    RelEnt,
    PltRel,
    Debug,
    TextRel,
    JmpRel,
    RunPath,
    Flags,
    /// Any tag not covered by the named variants.
    Other(u64),
}

impl From<u64> for DynamicTag {
    fn from(value: u64) -> Self {
        match value {
            DT_NULL => DynamicTag::Null,
            DT_NEEDED => DynamicTag::Needed,
            DT_PLTRELSZ => DynamicTag::PltRelSz,
            DT_PLTGOT => DynamicTag::PltGot,
            DT_HASH => DynamicTag::Hash,
            DT_STRTAB => DynamicTag::StrTab,
            DT_SYMTAB => DynamicTag::SymTab,
            DT_RELA => DynamicTag::Rela,
            DT_RELASZ => DynamicTag::RelaSz,
            DT_RELAENT => DynamicTag::RelaEnt,
            DT_STRSZ => DynamicTag::StrSz,
            DT_SYMENT => DynamicTag::SymEnt,
            DT_INIT => DynamicTag::Init,
            DT_FINI => DynamicTag::Fini,
            DT_SONAME => DynamicTag::SoName,
            DT_RPATH => DynamicTag::RPath,
            DT_SYMBOLIC => DynamicTag::Symbolic,
            DT_REL => DynamicTag::Rel,
            DT_RELSZ => DynamicTag::RelSz,
            DT_RELENT => DynamicTag::RelEnt,
            DT_PLTREL => DynamicTag::PltRel,
            DT_DEBUG => DynamicTag::Debug,
            DT_TEXTREL => DynamicTag::TextRel,
            DT_JMPREL => DynamicTag::JmpRel,
            DT_RUNPATH => DynamicTag::RunPath,
            DT_FLAGS => DynamicTag::Flags,
            other => DynamicTag::Other(other),
        }
    }
}

/// One `Elf(32|64)_Dyn` entry: a tag and its associated value.
pub struct DynamicEntry {
    /// `d_tag` — the dynamic entry kind (`DT_*`).
    pub d_tag: Field<u64>,
    /// `d_val` / `d_ptr` — the value or address associated with the tag.
    pub d_val: Field<u64>,
}

impl DynamicEntry {
    /// Raw `d_tag` value.
    pub fn tag(&self) -> u64 {
        self.d_tag.value
    }

    /// Typed interpretation of `d_tag`.
    pub fn tag_kind(&self) -> DynamicTag {
        DynamicTag::from(self.d_tag.value)
    }

    /// Raw `d_val` / `d_ptr` value.
    pub fn value(&self) -> u64 {
        self.d_val.value
    }

    /// Mutable accessor for `d_val` (`u32` on ELF32, `u64` on ELF64).
    pub fn value_mut(&mut self) -> NumericFieldMut<'_> {
        NumericFieldMut::U64(&mut self.d_val)
    }
}

/// The parsed `.dynamic` array (terminator excluded).
pub struct DynamicTable {
    /// File offset where the dynamic array starts.
    pub offset: usize,
    /// Entries up to and excluding `DT_NULL`.
    pub entries: Vec<DynamicEntry>,
}

impl DynamicTable {
    /// Parses `.dynamic` at `offset`, stopping at the `DT_NULL` terminator.
    ///
    /// `max_size` bounds the scan (the section size); parsing also stops when the buffer ends.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        max_size: usize,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        let ent_size = match class {
            ElfClass::Elf32 => 8,
            ElfClass::Elf64 => 16,
        };
        let end = offset
            .checked_add(max_size)
            .ok_or(FileParseError::BufferOverflow)?;

        let mut entries = Vec::new();
        let mut cursor = offset;
        loop {
            if cursor + ent_size > end || cursor + ent_size > buffer.len() {
                break;
            }
            let (tag, val, val_off, val_width) = match class {
                ElfClass::Elf32 => (
                    order.read_u32(buffer, cursor)? as u64,
                    order.read_u32(buffer, cursor + 4)? as u64,
                    cursor + 4,
                    4,
                ),
                ElfClass::Elf64 => (
                    order.read_u64(buffer, cursor)?,
                    order.read_u64(buffer, cursor + 8)?,
                    cursor + 8,
                    8,
                ),
            };

            let entry = DynamicEntry {
                d_tag: Field::new(tag, cursor, ent_size / 2),
                d_val: Field::new(val, val_off, val_width),
            };
            cursor += ent_size;

            if tag == DT_NULL {
                break;
            }
            entries.push(entry);
        }

        Ok(DynamicTable { offset, entries })
    }

    /// Returns the first entry matching `tag`, if present.
    pub fn find(&self, tag: u64) -> Option<&DynamicEntry> {
        self.entries.iter().find(|e| e.d_tag.value == tag)
    }
}
