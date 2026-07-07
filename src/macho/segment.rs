//! Abstractions over Mach-O segment load commands.
//!
//! [`SegmentEntry`] wraps 32-bit and 64-bit segment commands. Read with `vmaddr()`, `fileoff()`,
//! etc.; patch with the matching `*_mut()` accessor.

use super::load_command::LoadCommand;
use crate::errors;
use crate::field::{ByteOrder, Field, FieldMut, FixedBytes, NumericFieldMut};

pub mod prot {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 4;
}

#[derive(Debug)]
pub struct Segment32Fields {
    pub segname: Field<FixedBytes<16>>,
    pub vmaddr: Field<u32>,
    pub vmsize: Field<u32>,
    pub fileoff: Field<u32>,
    pub filesize: Field<u32>,
    pub maxprot: Field<u32>,
    pub initprot: Field<u32>,
    pub nsects: Field<u32>,
    pub flags: Field<u32>,
}

#[derive(Debug)]
pub struct Segment64Fields {
    pub segname: Field<FixedBytes<16>>,
    pub vmaddr: Field<u64>,
    pub vmsize: Field<u64>,
    pub fileoff: Field<u64>,
    pub filesize: Field<u64>,
    pub maxprot: Field<u32>,
    pub initprot: Field<u32>,
    pub nsects: Field<u32>,
    pub flags: Field<u32>,
}

/// Segment load command entry — 32-bit or 64-bit variant.
///
/// Use `fileoff()` to read and `fileoff_mut()` to patch; same pattern for all fields.
#[derive(Debug)]
pub enum SegmentEntry {
    Segment32(Segment32Fields),
    Segment64(Segment64Fields),
}

impl SegmentEntry {
    /// Returns the segment name from the 16-byte `segname` field.
    pub fn name(&self) -> &str {
        match self {
            SegmentEntry::Segment32(f) => f.segname.value.as_str(),
            SegmentEntry::Segment64(f) => f.segname.value.as_str(),
        }
    }

    pub fn vmaddr(&self) -> u64 {
        match self {
            SegmentEntry::Segment32(f) => f.vmaddr.value as u64,
            SegmentEntry::Segment64(f) => f.vmaddr.value,
        }
    }

    pub fn vmaddr_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SegmentEntry::Segment32(f) => NumericFieldMut::U32(&mut f.vmaddr),
            SegmentEntry::Segment64(f) => NumericFieldMut::U64(&mut f.vmaddr),
        }
    }

    /// On-disk width of `vmaddr` (4 or 8 bytes) — not a duplicate read accessor.
    pub fn vmaddr_size(&self) -> usize {
        match self {
            SegmentEntry::Segment32(f) => f.vmaddr.size,
            SegmentEntry::Segment64(f) => f.vmaddr.size,
        }
    }

    pub fn vmsize(&self) -> u64 {
        match self {
            SegmentEntry::Segment32(f) => f.vmsize.value as u64,
            SegmentEntry::Segment64(f) => f.vmsize.value,
        }
    }

    pub fn vmsize_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SegmentEntry::Segment32(f) => NumericFieldMut::U32(&mut f.vmsize),
            SegmentEntry::Segment64(f) => NumericFieldMut::U64(&mut f.vmsize),
        }
    }

    pub fn fileoff(&self) -> u64 {
        match self {
            SegmentEntry::Segment32(f) => f.fileoff.value as u64,
            SegmentEntry::Segment64(f) => f.fileoff.value,
        }
    }

    pub fn fileoff_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SegmentEntry::Segment32(f) => NumericFieldMut::U32(&mut f.fileoff),
            SegmentEntry::Segment64(f) => NumericFieldMut::U64(&mut f.fileoff),
        }
    }

    pub fn filesize(&self) -> u64 {
        match self {
            SegmentEntry::Segment32(f) => f.filesize.value as u64,
            SegmentEntry::Segment64(f) => f.filesize.value,
        }
    }

    pub fn filesize_mut(&mut self) -> NumericFieldMut<'_> {
        match self {
            SegmentEntry::Segment32(f) => NumericFieldMut::U32(&mut f.filesize),
            SegmentEntry::Segment64(f) => NumericFieldMut::U64(&mut f.filesize),
        }
    }

    pub fn maxprot(&self) -> u32 {
        match self {
            SegmentEntry::Segment32(f) => f.maxprot.value,
            SegmentEntry::Segment64(f) => f.maxprot.value,
        }
    }

    pub fn maxprot_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SegmentEntry::Segment32(f) => FieldMut::<u32>::new(&mut f.maxprot),
            SegmentEntry::Segment64(f) => FieldMut::<u32>::new(&mut f.maxprot),
        }
    }

    pub fn initprot(&self) -> u32 {
        match self {
            SegmentEntry::Segment32(f) => f.initprot.value,
            SegmentEntry::Segment64(f) => f.initprot.value,
        }
    }

    pub fn initprot_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SegmentEntry::Segment32(f) => FieldMut::<u32>::new(&mut f.initprot),
            SegmentEntry::Segment64(f) => FieldMut::<u32>::new(&mut f.initprot),
        }
    }

    pub fn nsects(&self) -> u32 {
        match self {
            SegmentEntry::Segment32(f) => f.nsects.value,
            SegmentEntry::Segment64(f) => f.nsects.value,
        }
    }

    pub fn nsects_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SegmentEntry::Segment32(f) => FieldMut::<u32>::new(&mut f.nsects),
            SegmentEntry::Segment64(f) => FieldMut::<u32>::new(&mut f.nsects),
        }
    }

    pub fn flags(&self) -> u32 {
        match self {
            SegmentEntry::Segment32(f) => f.flags.value,
            SegmentEntry::Segment64(f) => f.flags.value,
        }
    }

    pub fn flags_mut(&mut self) -> FieldMut<'_, u32> {
        match self {
            SegmentEntry::Segment32(f) => FieldMut::<u32>::new(&mut f.flags),
            SegmentEntry::Segment64(f) => FieldMut::<u32>::new(&mut f.flags),
        }
    }

    pub(crate) fn parse_segments(
        buffer: &[u8],
        load_commands: &[LoadCommand],
        order: ByteOrder,
    ) -> Result<Vec<Self>, errors::FileParseError> {
        let mut segments = Vec::new();

        for cmd in load_commands {
            let offset = cmd.cmd.offset;

            if cmd.cmd.value == 0x1 {
                let segname = FixedBytes::from_slice(&buffer[offset + 8..offset + 24]);

                segments.push(SegmentEntry::Segment32(Segment32Fields {
                    segname: Field::new(segname, offset + 8, 16),
                    vmaddr: Field::new(order.read_u32(buffer, offset + 24)?, offset + 24, 4),
                    vmsize: Field::new(order.read_u32(buffer, offset + 28)?, offset + 28, 4),
                    fileoff: Field::new(order.read_u32(buffer, offset + 32)?, offset + 32, 4),
                    filesize: Field::new(order.read_u32(buffer, offset + 36)?, offset + 36, 4),
                    maxprot: Field::new(order.read_u32(buffer, offset + 40)?, offset + 40, 4),
                    initprot: Field::new(order.read_u32(buffer, offset + 44)?, offset + 44, 4),
                    nsects: Field::new(order.read_u32(buffer, offset + 48)?, offset + 48, 4),
                    flags: Field::new(order.read_u32(buffer, offset + 52)?, offset + 52, 4),
                }));
            } else if cmd.cmd.value == 0x19 {
                let segname = FixedBytes::from_slice(&buffer[offset + 8..offset + 24]);

                segments.push(SegmentEntry::Segment64(Segment64Fields {
                    segname: Field::new(segname, offset + 8, 16),
                    vmaddr: Field::new(order.read_u64(buffer, offset + 24)?, offset + 24, 8),
                    vmsize: Field::new(order.read_u64(buffer, offset + 32)?, offset + 32, 8),
                    fileoff: Field::new(order.read_u64(buffer, offset + 40)?, offset + 40, 8),
                    filesize: Field::new(order.read_u64(buffer, offset + 48)?, offset + 48, 8),
                    maxprot: Field::new(order.read_u32(buffer, offset + 56)?, offset + 56, 4),
                    initprot: Field::new(order.read_u32(buffer, offset + 60)?, offset + 60, 4),
                    nsects: Field::new(order.read_u32(buffer, offset + 64)?, offset + 64, 4),
                    flags: Field::new(order.read_u32(buffer, offset + 68)?, offset + 68, 4),
                }));
            }
        }

        Ok(segments)
    }
}

/// Input for [`crate::macho::MachO::insert_segment`].
pub struct NewSegment {
    /// Segment name (truncated to 16 bytes on disk).
    pub name: String,
    /// Segment data appended at the end of the file.
    pub data: Vec<u8>,
    /// Initial memory protection (`initprot`).
    pub initprot: u32,
    /// Maximum memory protection (`maxprot`).
    pub maxprot: u32,
}
