//! ELF program headers (`Phdr`).
//!
//! [`ProgramHeaderEntry`] wraps ELF32 and ELF64 layouts. Read with `p_*()` methods; patch with
//! the matching `p_*_mut()` accessor and [`crate::field::NumericFieldMut::update_with`].

use super::header::ElfClass;
use crate::errors;
use crate::field::{ByteOrder, Field, FieldMut, NumericFieldMut};

/// `PT_NULL` — unused program header entry.
pub const PT_NULL: u32 = 0;
/// `PT_LOAD` segment type.
pub const PT_LOAD: u32 = 1;
/// `PT_DYNAMIC` — dynamic linking information.
pub const PT_DYNAMIC: u32 = 2;
/// `PT_INTERP` — program interpreter path.
pub const PT_INTERP: u32 = 3;
/// `PT_NOTE` — auxiliary note information.
pub const PT_NOTE: u32 = 4;
/// `PT_SHLIB` — reserved, unspecified semantics.
pub const PT_SHLIB: u32 = 5;
/// `PT_PHDR` — the program header table itself.
pub const PT_PHDR: u32 = 6;
/// `PT_TLS` — thread-local storage template.
pub const PT_TLS: u32 = 7;
/// `PT_GNU_EH_FRAME` — GNU exception handling frame.
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
/// `PT_GNU_STACK` — stack executability flags.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// `PT_GNU_RELRO` — read-only after relocation region.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
/// `PT_GNU_PROPERTY` — GNU property note segment.
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;

pub mod segment_flags {
    pub const READ: u32 = 4;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 1;
}

/// Typed view of `p_type` for the common segment kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Shlib,
    Phdr,
    Tls,
    GnuEhFrame,
    GnuStack,
    GnuRelro,
    GnuProperty,
    /// Any `p_type` not covered by the named variants.
    Other(u32),
}

impl From<u32> for SegmentType {
    fn from(value: u32) -> Self {
        match value {
            PT_NULL => SegmentType::Null,
            PT_LOAD => SegmentType::Load,
            PT_DYNAMIC => SegmentType::Dynamic,
            PT_INTERP => SegmentType::Interp,
            PT_NOTE => SegmentType::Note,
            PT_SHLIB => SegmentType::Shlib,
            PT_PHDR => SegmentType::Phdr,
            PT_TLS => SegmentType::Tls,
            PT_GNU_EH_FRAME => SegmentType::GnuEhFrame,
            PT_GNU_STACK => SegmentType::GnuStack,
            PT_GNU_RELRO => SegmentType::GnuRelro,
            PT_GNU_PROPERTY => SegmentType::GnuProperty,
            other => SegmentType::Other(other),
        }
    }
}

/// ELF32 program header fields.
#[derive(Debug)]
pub struct Phdr32Fields {
    pub p_type: Field<u32>,
    pub p_offset: Field<u32>,
    pub p_vaddr: Field<u32>,
    pub p_paddr: Field<u32>,
    pub p_filesz: Field<u32>,
    pub p_memsz: Field<u32>,
    pub p_flags: Field<u32>,
    pub p_align: Field<u32>,
}

/// ELF64 program header fields.
#[derive(Debug)]
pub struct Phdr64Fields {
    pub p_type: Field<u32>,
    pub p_flags: Field<u32>,
    pub p_offset: Field<u64>,
    pub p_vaddr: Field<u64>,
    pub p_paddr: Field<u64>,
    pub p_filesz: Field<u64>,
    pub p_memsz: Field<u64>,
    pub p_align: Field<u64>,
}

/// Program header entry — ELF32 or ELF64 variant.
///
/// Use `p_offset()` to read and `p_offset_mut()` to patch; same pattern for all `p_*` fields.
#[derive(Debug)]
pub enum ProgramHeaderEntry {
    Phdr32(Phdr32Fields),
    Phdr64(Phdr64Fields),
}

impl ProgramHeaderEntry {
    pub fn p_type(&self) -> u32 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_type.value,
            ProgramHeaderEntry::Phdr64(f) => f.p_type.value,
        }
    }

    pub fn p_type_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => FieldMut::<u32>::new(&mut f.p_type),
            ProgramHeaderEntry::Phdr64(f) => FieldMut::<u32>::new(&mut f.p_type),
        }
    }

    /// Typed interpretation of [`p_type`](Self::p_type).
    pub fn segment_type(&self) -> SegmentType {
        SegmentType::from(self.p_type())
    }

    pub fn p_flags(&self) -> u32 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_flags.value,
            ProgramHeaderEntry::Phdr64(f) => f.p_flags.value,
        }
    }

    pub fn p_flags_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => FieldMut::<u32>::new(&mut f.p_flags),
            ProgramHeaderEntry::Phdr64(f) => FieldMut::<u32>::new(&mut f.p_flags),
        }
    }

    pub fn p_offset(&self) -> u64 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_offset.value as u64,
            ProgramHeaderEntry::Phdr64(f) => f.p_offset.value,
        }
    }

    pub fn p_offset_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => NumericFieldMut::U32(&mut f.p_offset),
            ProgramHeaderEntry::Phdr64(f) => NumericFieldMut::U64(&mut f.p_offset),
        }
    }

    pub fn p_vaddr(&self) -> u64 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_vaddr.value as u64,
            ProgramHeaderEntry::Phdr64(f) => f.p_vaddr.value,
        }
    }

    pub fn p_vaddr_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => NumericFieldMut::U32(&mut f.p_vaddr),
            ProgramHeaderEntry::Phdr64(f) => NumericFieldMut::U64(&mut f.p_vaddr),
        }
    }

    pub fn p_paddr(&self) -> u64 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_paddr.value as u64,
            ProgramHeaderEntry::Phdr64(f) => f.p_paddr.value,
        }
    }

    pub fn p_paddr_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => NumericFieldMut::U32(&mut f.p_paddr),
            ProgramHeaderEntry::Phdr64(f) => NumericFieldMut::U64(&mut f.p_paddr),
        }
    }

    pub fn p_filesz(&self) -> u64 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_filesz.value as u64,
            ProgramHeaderEntry::Phdr64(f) => f.p_filesz.value,
        }
    }

    pub fn p_filesz_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => NumericFieldMut::U32(&mut f.p_filesz),
            ProgramHeaderEntry::Phdr64(f) => NumericFieldMut::U64(&mut f.p_filesz),
        }
    }

    pub fn p_memsz(&self) -> u64 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_memsz.value as u64,
            ProgramHeaderEntry::Phdr64(f) => f.p_memsz.value,
        }
    }

    pub fn p_memsz_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => NumericFieldMut::U32(&mut f.p_memsz),
            ProgramHeaderEntry::Phdr64(f) => NumericFieldMut::U64(&mut f.p_memsz),
        }
    }

    pub fn p_align(&self) -> u64 {
        match self {
            ProgramHeaderEntry::Phdr32(f) => f.p_align.value as u64,
            ProgramHeaderEntry::Phdr64(f) => f.p_align.value,
        }
    }

    pub fn p_align_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            ProgramHeaderEntry::Phdr32(f) => NumericFieldMut::U32(&mut f.p_align),
            ProgramHeaderEntry::Phdr64(f) => NumericFieldMut::U64(&mut f.p_align),
        }
    }

    pub(crate) fn parse_program_headers(
        buffer: &[u8],
        offset: u64,
        size: u16,
        count: u16,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<Vec<ProgramHeaderEntry>, errors::FileParseError> {
        let mut headers = Vec::new();
        let start = offset as usize;

        for i in 0..count as usize {
            let base = start + i * size as usize;
            if buffer.len() < base + size as usize {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let header = match class {
                ElfClass::Elf32 => ProgramHeaderEntry::Phdr32(Phdr32Fields {
                    p_type: Field::new(order.read_u32_slice(&buffer[base..base + 4])?, base, 4),
                    p_offset: Field::new(
                        order.read_u32_slice(&buffer[base + 4..base + 8])?,
                        base + 4,
                        4,
                    ),
                    p_vaddr: Field::new(
                        order.read_u32_slice(&buffer[base + 8..base + 12])?,
                        base + 8,
                        4,
                    ),
                    p_paddr: Field::new(
                        order.read_u32_slice(&buffer[base + 12..base + 16])?,
                        base + 12,
                        4,
                    ),
                    p_filesz: Field::new(
                        order.read_u32_slice(&buffer[base + 16..base + 20])?,
                        base + 16,
                        4,
                    ),
                    p_memsz: Field::new(
                        order.read_u32_slice(&buffer[base + 20..base + 24])?,
                        base + 20,
                        4,
                    ),
                    p_flags: Field::new(
                        order.read_u32_slice(&buffer[base + 24..base + 28])?,
                        base + 24,
                        4,
                    ),
                    p_align: Field::new(
                        order.read_u32_slice(&buffer[base + 28..base + 32])?,
                        base + 28,
                        4,
                    ),
                }),
                ElfClass::Elf64 => ProgramHeaderEntry::Phdr64(Phdr64Fields {
                    p_type: Field::new(order.read_u32_slice(&buffer[base..base + 4])?, base, 4),
                    p_flags: Field::new(
                        order.read_u32_slice(&buffer[base + 4..base + 8])?,
                        base + 4,
                        4,
                    ),
                    p_offset: Field::new(
                        order.read_u64_slice(&buffer[base + 8..base + 16])?,
                        base + 8,
                        8,
                    ),
                    p_vaddr: Field::new(
                        order.read_u64_slice(&buffer[base + 16..base + 24])?,
                        base + 16,
                        8,
                    ),
                    p_paddr: Field::new(
                        order.read_u64_slice(&buffer[base + 24..base + 32])?,
                        base + 24,
                        8,
                    ),
                    p_filesz: Field::new(
                        order.read_u64_slice(&buffer[base + 32..base + 40])?,
                        base + 32,
                        8,
                    ),
                    p_memsz: Field::new(
                        order.read_u64_slice(&buffer[base + 40..base + 48])?,
                        base + 40,
                        8,
                    ),
                    p_align: Field::new(
                        order.read_u64_slice(&buffer[base + 48..base + 56])?,
                        base + 48,
                        8,
                    ),
                }),
            };

            headers.push(header);
        }

        Ok(headers)
    }
}

/// Input for [`crate::elf::ELF::insert_pt_load`].
pub struct NewPtLoad {
    /// Segment data appended at the end of the file.
    pub data: Vec<u8>,
    /// `p_flags` (`PF_*`).
    pub flags: u32,
    /// Virtual address; computed from the last `PT_LOAD` if `None`.
    pub vaddr: Option<u64>,
    /// Alignment; taken from the last `PT_LOAD` or `0x1000` if `None`.
    pub align: Option<u64>,
}
