//! Mach-O `section` / `section_64` records nested inside segment load commands.
//!
//! Read fields with `addr()`, `offset()`, etc.; the on-disk width of address/size fields depends
//! on the parent segment kind (4 bytes for `section`, 8 for `section_64`).

use super::load_command::{LoadCommand, LC_SEGMENT, LC_SEGMENT_64};
use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field, FixedBytes, NumericFieldMut};

/// `section` — 68 bytes, nested under `LC_SEGMENT`.
#[derive(Debug)]
pub struct Section32Fields {
    pub sectname: Field<FixedBytes<16>>,
    pub segname: Field<FixedBytes<16>>,
    pub addr: Field<u32>,
    pub size: Field<u32>,
    pub offset: Field<u32>,
    pub align: Field<u32>,
    pub reloff: Field<u32>,
    pub nreloc: Field<u32>,
    pub flags: Field<u32>,
}

/// `section_64` — 80 bytes, nested under `LC_SEGMENT_64`.
#[derive(Debug)]
pub struct Section64Fields {
    pub sectname: Field<FixedBytes<16>>,
    pub segname: Field<FixedBytes<16>>,
    pub addr: Field<u64>,
    pub size: Field<u64>,
    pub offset: Field<u32>,
    pub align: Field<u32>,
    pub reloff: Field<u32>,
    pub nreloc: Field<u32>,
    pub flags: Field<u32>,
}

/// A `section` / `section_64` record — 32-bit or 64-bit variant.
#[derive(Debug)]
pub enum SectionEntry {
    Section32(Section32Fields),
    Section64(Section64Fields),
}

impl SectionEntry {
    /// On-disk size of a `section` record in bytes for the given segment kind.
    fn record_size(is_64: bool) -> usize {
        if is_64 {
            80
        } else {
            68
        }
    }

    /// Section name (`sectname`).
    pub fn name(&self) -> &str {
        match self {
            SectionEntry::Section32(f) => f.sectname.value.as_str(),
            SectionEntry::Section64(f) => f.sectname.value.as_str(),
        }
    }

    /// Parent segment name (`segname`).
    pub fn segment_name(&self) -> &str {
        match self {
            SectionEntry::Section32(f) => f.segname.value.as_str(),
            SectionEntry::Section64(f) => f.segname.value.as_str(),
        }
    }

    /// Virtual address (`addr`).
    pub fn addr(&self) -> u64 {
        match self {
            SectionEntry::Section32(f) => f.addr.value as u64,
            SectionEntry::Section64(f) => f.addr.value,
        }
    }

    pub fn addr_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionEntry::Section32(f) => NumericFieldMut::U32(&mut f.addr),
            SectionEntry::Section64(f) => NumericFieldMut::U64(&mut f.addr),
        }
    }

    /// Section size in bytes (`size`).
    pub fn size(&self) -> u64 {
        match self {
            SectionEntry::Section32(f) => f.size.value as u64,
            SectionEntry::Section64(f) => f.size.value,
        }
    }

    pub fn size_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SectionEntry::Section32(f) => NumericFieldMut::U32(&mut f.size),
            SectionEntry::Section64(f) => NumericFieldMut::U64(&mut f.size),
        }
    }

    /// File offset of the section data (`offset`); `0` for zero-fill sections.
    pub fn offset(&self) -> u32 {
        match self {
            SectionEntry::Section32(f) => f.offset.value,
            SectionEntry::Section64(f) => f.offset.value,
        }
    }

    /// File offset of the relocation entries (`reloff`).
    pub fn reloff(&self) -> u32 {
        match self {
            SectionEntry::Section32(f) => f.reloff.value,
            SectionEntry::Section64(f) => f.reloff.value,
        }
    }

    /// Number of relocation entries (`nreloc`).
    pub fn nreloc(&self) -> u32 {
        match self {
            SectionEntry::Section32(f) => f.nreloc.value,
            SectionEntry::Section64(f) => f.nreloc.value,
        }
    }

    /// Section flags (`flags`).
    pub fn flags(&self) -> u32 {
        match self {
            SectionEntry::Section32(f) => f.flags.value,
            SectionEntry::Section64(f) => f.flags.value,
        }
    }

    fn parse_one(
        buffer: &[u8],
        offset: usize,
        is_64: bool,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::record_size(is_64) {
            return Err(FileParseError::BufferOverflow);
        }

        let sectname = FixedBytes::from_slice(&buffer[offset..offset + 16]);
        let segname = FixedBytes::from_slice(&buffer[offset + 16..offset + 32]);

        if is_64 {
            Ok(SectionEntry::Section64(Section64Fields {
                sectname: Field::new(sectname, offset, 16),
                segname: Field::new(segname, offset + 16, 16),
                addr: Field::new(order.read_u64(buffer, offset + 32)?, offset + 32, 8),
                size: Field::new(order.read_u64(buffer, offset + 40)?, offset + 40, 8),
                offset: Field::new(order.read_u32(buffer, offset + 48)?, offset + 48, 4),
                align: Field::new(order.read_u32(buffer, offset + 52)?, offset + 52, 4),
                reloff: Field::new(order.read_u32(buffer, offset + 56)?, offset + 56, 4),
                nreloc: Field::new(order.read_u32(buffer, offset + 60)?, offset + 60, 4),
                flags: Field::new(order.read_u32(buffer, offset + 64)?, offset + 64, 4),
            }))
        } else {
            Ok(SectionEntry::Section32(Section32Fields {
                sectname: Field::new(sectname, offset, 16),
                segname: Field::new(segname, offset + 16, 16),
                addr: Field::new(order.read_u32(buffer, offset + 32)?, offset + 32, 4),
                size: Field::new(order.read_u32(buffer, offset + 36)?, offset + 36, 4),
                offset: Field::new(order.read_u32(buffer, offset + 40)?, offset + 40, 4),
                align: Field::new(order.read_u32(buffer, offset + 44)?, offset + 44, 4),
                reloff: Field::new(order.read_u32(buffer, offset + 48)?, offset + 48, 4),
                nreloc: Field::new(order.read_u32(buffer, offset + 52)?, offset + 52, 4),
                flags: Field::new(order.read_u32(buffer, offset + 56)?, offset + 56, 4),
            }))
        }
    }

    /// Parses every `section` / `section_64` nested inside the segment load commands.
    pub(crate) fn parse_sections(
        buffer: &[u8],
        load_commands: &[LoadCommand],
        order: ByteOrder,
    ) -> Result<Vec<Self>, FileParseError> {
        let mut sections = Vec::new();

        for cmd in load_commands {
            let is_64 = match cmd.cmd.value {
                LC_SEGMENT => false,
                LC_SEGMENT_64 => true,
                _ => continue,
            };

            let seg_off = cmd.cmd.offset;
            // nsects lives at a different offset per segment kind.
            let nsects_off = if is_64 { seg_off + 64 } else { seg_off + 48 };
            let nsects = order.read_u32(buffer, nsects_off)?;
            let header_size = if is_64 { 72 } else { 56 };
            let mut sect_off = seg_off + header_size;

            for _ in 0..nsects {
                let section = Self::parse_one(buffer, sect_off, is_64, order)?;
                sect_off += Self::record_size(is_64);
                sections.push(section);
            }
        }

        Ok(sections)
    }
}
