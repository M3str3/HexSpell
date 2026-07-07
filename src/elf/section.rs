//! ELF section headers (`Shdr`).
//!
//! [`SectionHeaderEntry`] wraps ELF32 and ELF64 layouts. Read with `sh_*()` methods; patch with
//! the matching `sh_*_mut()` accessor.

use super::header::ElfClass;
use crate::errors;
use crate::field::{ByteOrder, Field, FieldMut, NumericFieldMut};

/// `SHT_NULL` — inactive section header.
pub const SHT_NULL: u32 = 0;
/// `SHT_PROGBITS` section type.
pub const SHT_PROGBITS: u32 = 1;
/// `SHT_SYMTAB` — symbol table.
pub const SHT_SYMTAB: u32 = 2;
/// `SHT_STRTAB` — string table.
pub const SHT_STRTAB: u32 = 3;
/// `SHT_RELA` — relocations with addends.
pub const SHT_RELA: u32 = 4;
/// `SHT_HASH` — symbol hash table.
pub const SHT_HASH: u32 = 5;
/// `SHT_DYNAMIC` — dynamic linking information.
pub const SHT_DYNAMIC: u32 = 6;
/// `SHT_NOTE` — note section.
pub const SHT_NOTE: u32 = 7;
/// `SHT_NOBITS` — occupies no file space (e.g. `.bss`).
pub const SHT_NOBITS: u32 = 8;
/// `SHT_REL` — relocations without addends.
pub const SHT_REL: u32 = 9;
/// `SHT_DYNSYM` — dynamic linker symbol table.
pub const SHT_DYNSYM: u32 = 11;
/// `SHT_INIT_ARRAY` — array of initialization functions.
pub const SHT_INIT_ARRAY: u32 = 14;
/// `SHT_FINI_ARRAY` — array of termination functions.
pub const SHT_FINI_ARRAY: u32 = 15;
/// `SHT_PREINIT_ARRAY` — array of pre-initialization functions.
pub const SHT_PREINIT_ARRAY: u32 = 16;
/// `SHT_GROUP` — section group / COMDAT metadata.
pub const SHT_GROUP: u32 = 17;
/// `SHT_GNU_HASH` — GNU-style symbol hash table.
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
/// `SHT_GNU_VERDEF` — version definitions (`.gnu.version_d`).
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
/// `SHT_GNU_VERSYM` — symbol version table (`.gnu.version`).
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
/// `SHT_GNU_VERNEED` — required version definitions (`.gnu.version_r`).
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;

pub mod section_flags {
    pub const WRITE: u64 = 1;
    pub const ALLOC: u64 = 2;
    pub const EXECINSTR: u64 = 4;
    pub const GROUP: u64 = 0x200;
}

/// Typed view of `sh_type` for the common section kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Null,
    Progbits,
    Symtab,
    Strtab,
    Rela,
    Hash,
    Dynamic,
    Note,
    Nobits,
    Rel,
    Dynsym,
    InitArray,
    FiniArray,
    PreinitArray,
    Group,
    GnuHash,
    GnuVerdef,
    GnuVersym,
    GnuVerneed,
    /// Any `sh_type` not covered by the named variants.
    Other(u32),
}

impl From<u32> for SectionType {
    fn from(value: u32) -> Self {
        match value {
            SHT_NULL => SectionType::Null,
            SHT_PROGBITS => SectionType::Progbits,
            SHT_SYMTAB => SectionType::Symtab,
            SHT_STRTAB => SectionType::Strtab,
            SHT_RELA => SectionType::Rela,
            SHT_HASH => SectionType::Hash,
            SHT_DYNAMIC => SectionType::Dynamic,
            SHT_NOTE => SectionType::Note,
            SHT_NOBITS => SectionType::Nobits,
            SHT_REL => SectionType::Rel,
            SHT_DYNSYM => SectionType::Dynsym,
            SHT_INIT_ARRAY => SectionType::InitArray,
            SHT_FINI_ARRAY => SectionType::FiniArray,
            SHT_PREINIT_ARRAY => SectionType::PreinitArray,
            SHT_GROUP => SectionType::Group,
            SHT_GNU_HASH => SectionType::GnuHash,
            SHT_GNU_VERDEF => SectionType::GnuVerdef,
            SHT_GNU_VERSYM => SectionType::GnuVersym,
            SHT_GNU_VERNEED => SectionType::GnuVerneed,
            other => SectionType::Other(other),
        }
    }
}

#[derive(Debug)]
pub struct Shdr32Fields {
    pub sh_name: Field<u32>,
    pub sh_type: Field<u32>,
    pub sh_flags: Field<u32>,
    pub sh_addr: Field<u32>,
    pub sh_offset: Field<u32>,
    pub sh_size: Field<u32>,
    pub sh_link: Field<u32>,
    pub sh_info: Field<u32>,
    pub sh_addralign: Field<u32>,
    pub sh_entsize: Field<u32>,
}

#[derive(Debug)]
pub struct Shdr64Fields {
    pub sh_name: Field<u32>,
    pub sh_type: Field<u32>,
    pub sh_flags: Field<u64>,
    pub sh_addr: Field<u64>,
    pub sh_offset: Field<u64>,
    pub sh_size: Field<u64>,
    pub sh_link: Field<u32>,
    pub sh_info: Field<u32>,
    pub sh_addralign: Field<u64>,
    pub sh_entsize: Field<u64>,
}

/// Section header entry — ELF32 or ELF64 variant.
///
/// Use `sh_offset()` to read and `sh_offset_mut()` to patch; same pattern for all `sh_*` fields.
#[derive(Debug)]
pub enum SectionHeaderEntry {
    Shdr32(Shdr32Fields),
    Shdr64(Shdr64Fields),
}

impl SectionHeaderEntry {
    pub fn sh_name(&self) -> u32 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_name.value,
            SectionHeaderEntry::Shdr64(f) => f.sh_name.value,
        }
    }

    pub fn sh_name_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SectionHeaderEntry::Shdr32(f) => FieldMut::<u32>::new(&mut f.sh_name),
            SectionHeaderEntry::Shdr64(f) => FieldMut::<u32>::new(&mut f.sh_name),
        }
    }

    pub fn sh_type(&self) -> u32 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_type.value,
            SectionHeaderEntry::Shdr64(f) => f.sh_type.value,
        }
    }

    pub fn sh_type_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SectionHeaderEntry::Shdr32(f) => FieldMut::<u32>::new(&mut f.sh_type),
            SectionHeaderEntry::Shdr64(f) => FieldMut::<u32>::new(&mut f.sh_type),
        }
    }

    /// Typed interpretation of [`sh_type`](Self::sh_type).
    pub fn section_type(&self) -> SectionType {
        SectionType::from(self.sh_type())
    }

    pub fn sh_flags(&self) -> u64 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_flags.value as u64,
            SectionHeaderEntry::Shdr64(f) => f.sh_flags.value,
        }
    }

    pub fn sh_flags_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionHeaderEntry::Shdr32(f) => NumericFieldMut::U32(&mut f.sh_flags),
            SectionHeaderEntry::Shdr64(f) => NumericFieldMut::U64(&mut f.sh_flags),
        }
    }

    pub fn sh_addr(&self) -> u64 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_addr.value as u64,
            SectionHeaderEntry::Shdr64(f) => f.sh_addr.value,
        }
    }

    pub fn sh_addr_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionHeaderEntry::Shdr32(f) => NumericFieldMut::U32(&mut f.sh_addr),
            SectionHeaderEntry::Shdr64(f) => NumericFieldMut::U64(&mut f.sh_addr),
        }
    }

    pub fn sh_offset(&self) -> u64 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_offset.value as u64,
            SectionHeaderEntry::Shdr64(f) => f.sh_offset.value,
        }
    }

    pub fn sh_offset_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionHeaderEntry::Shdr32(f) => NumericFieldMut::U32(&mut f.sh_offset),
            SectionHeaderEntry::Shdr64(f) => NumericFieldMut::U64(&mut f.sh_offset),
        }
    }

    pub fn sh_size(&self) -> u64 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_size.value as u64,
            SectionHeaderEntry::Shdr64(f) => f.sh_size.value,
        }
    }

    pub fn sh_size_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionHeaderEntry::Shdr32(f) => NumericFieldMut::U32(&mut f.sh_size),
            SectionHeaderEntry::Shdr64(f) => NumericFieldMut::U64(&mut f.sh_size),
        }
    }

    pub fn sh_link(&self) -> u32 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_link.value,
            SectionHeaderEntry::Shdr64(f) => f.sh_link.value,
        }
    }

    pub fn sh_link_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SectionHeaderEntry::Shdr32(f) => FieldMut::<u32>::new(&mut f.sh_link),
            SectionHeaderEntry::Shdr64(f) => FieldMut::<u32>::new(&mut f.sh_link),
        }
    }

    pub fn sh_info(&self) -> u32 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_info.value,
            SectionHeaderEntry::Shdr64(f) => f.sh_info.value,
        }
    }

    pub fn sh_info_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SectionHeaderEntry::Shdr32(f) => FieldMut::<u32>::new(&mut f.sh_info),
            SectionHeaderEntry::Shdr64(f) => FieldMut::<u32>::new(&mut f.sh_info),
        }
    }

    pub fn sh_addralign(&self) -> u64 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_addralign.value as u64,
            SectionHeaderEntry::Shdr64(f) => f.sh_addralign.value,
        }
    }

    pub fn sh_addralign_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionHeaderEntry::Shdr32(f) => NumericFieldMut::U32(&mut f.sh_addralign),
            SectionHeaderEntry::Shdr64(f) => NumericFieldMut::U64(&mut f.sh_addralign),
        }
    }

    pub fn sh_entsize(&self) -> u64 {
        match self {
            SectionHeaderEntry::Shdr32(f) => f.sh_entsize.value as u64,
            SectionHeaderEntry::Shdr64(f) => f.sh_entsize.value,
        }
    }

    pub fn sh_entsize_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionHeaderEntry::Shdr32(f) => NumericFieldMut::U32(&mut f.sh_entsize),
            SectionHeaderEntry::Shdr64(f) => NumericFieldMut::U64(&mut f.sh_entsize),
        }
    }

    pub(crate) fn parse_section_headers(
        buffer: &[u8],
        offset: u64,
        size: u16,
        count: usize,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<Vec<SectionHeaderEntry>, errors::FileParseError> {
        let mut headers = Vec::new();
        let start = offset as usize;

        for i in 0..count {
            let base = start + i * size as usize;
            if buffer.len() < base + size as usize {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let header = match class {
                ElfClass::Elf32 => SectionHeaderEntry::Shdr32(Shdr32Fields {
                    sh_name: Field::new(order.read_u32_slice(&buffer[base..base + 4])?, base, 4),
                    sh_type: Field::new(
                        order.read_u32_slice(&buffer[base + 4..base + 8])?,
                        base + 4,
                        4,
                    ),
                    sh_flags: Field::new(
                        order.read_u32_slice(&buffer[base + 8..base + 12])?,
                        base + 8,
                        4,
                    ),
                    sh_addr: Field::new(
                        order.read_u32_slice(&buffer[base + 12..base + 16])?,
                        base + 12,
                        4,
                    ),
                    sh_offset: Field::new(
                        order.read_u32_slice(&buffer[base + 16..base + 20])?,
                        base + 16,
                        4,
                    ),
                    sh_size: Field::new(
                        order.read_u32_slice(&buffer[base + 20..base + 24])?,
                        base + 20,
                        4,
                    ),
                    sh_link: Field::new(
                        order.read_u32_slice(&buffer[base + 24..base + 28])?,
                        base + 24,
                        4,
                    ),
                    sh_info: Field::new(
                        order.read_u32_slice(&buffer[base + 28..base + 32])?,
                        base + 28,
                        4,
                    ),
                    sh_addralign: Field::new(
                        order.read_u32_slice(&buffer[base + 32..base + 36])?,
                        base + 32,
                        4,
                    ),
                    sh_entsize: Field::new(
                        order.read_u32_slice(&buffer[base + 36..base + 40])?,
                        base + 36,
                        4,
                    ),
                }),
                ElfClass::Elf64 => SectionHeaderEntry::Shdr64(Shdr64Fields {
                    sh_name: Field::new(order.read_u32_slice(&buffer[base..base + 4])?, base, 4),
                    sh_type: Field::new(
                        order.read_u32_slice(&buffer[base + 4..base + 8])?,
                        base + 4,
                        4,
                    ),
                    sh_flags: Field::new(
                        order.read_u64_slice(&buffer[base + 8..base + 16])?,
                        base + 8,
                        8,
                    ),
                    sh_addr: Field::new(
                        order.read_u64_slice(&buffer[base + 16..base + 24])?,
                        base + 16,
                        8,
                    ),
                    sh_offset: Field::new(
                        order.read_u64_slice(&buffer[base + 24..base + 32])?,
                        base + 24,
                        8,
                    ),
                    sh_size: Field::new(
                        order.read_u64_slice(&buffer[base + 32..base + 40])?,
                        base + 32,
                        8,
                    ),
                    sh_link: Field::new(
                        order.read_u32_slice(&buffer[base + 40..base + 44])?,
                        base + 40,
                        4,
                    ),
                    sh_info: Field::new(
                        order.read_u32_slice(&buffer[base + 44..base + 48])?,
                        base + 44,
                        4,
                    ),
                    sh_addralign: Field::new(
                        order.read_u64_slice(&buffer[base + 48..base + 56])?,
                        base + 48,
                        8,
                    ),
                    sh_entsize: Field::new(
                        order.read_u64_slice(&buffer[base + 56..base + 64])?,
                        base + 56,
                        8,
                    ),
                }),
            };

            headers.push(header);
        }

        Ok(headers)
    }
}

/// Input for [`crate::elf::ELF::insert_section`].
pub struct NewSection {
    /// Section name (stored in `.shstrtab`).
    pub name: String,
    /// Section contents.
    pub data: Vec<u8>,
    /// `sh_type` (`SHT_*`).
    pub sh_type: u32,
    /// `sh_flags` (`SHF_*`).
    pub flags: u64,
    /// Optional virtual address for `sh_addr`; defaults to `0`.
    pub addr: Option<u64>,
    /// Optional file offset. Defaults to appending the contents.
    pub offset: Option<u64>,
    /// Optional section link (`sh_link`); defaults to `0`.
    pub link: Option<u32>,
    /// Optional section info (`sh_info`); defaults to `0`.
    pub info: Option<u32>,
    /// Optional section alignment (`sh_addralign`); defaults to `1`.
    pub addralign: Option<u64>,
    /// Optional entry size (`sh_entsize`); defaults to `0`.
    pub entsize: Option<u64>,
}
