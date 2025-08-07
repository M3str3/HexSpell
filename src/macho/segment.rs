//! Abstractions over Mach-O segments.
//!
//! Segments describe ranges of virtual memory and how the corresponding
//! bytes appear in the file. This module interprets `LC_SEGMENT` and
//! `LC_SEGMENT_64` commands into [`Segment`] structures with readable
//! fields for addresses, sizes and protection flags, enabling precise
//! modifications when rewriting binaries.

use super::header::Endianness;
use super::load_command::LoadCommand;
use crate::errors;
use crate::field::Field;

#[derive(Debug)]
pub struct Segment {
    pub name: String,
    pub vmaddr: Field<u64>,
    pub vmsize: Field<u64>,
    pub fileoff: Field<u64>,
    pub filesize: Field<u64>,
    pub maxprot: Field<u32>,
    pub initprot: Field<u32>,
    pub nsects: Field<u32>,
    pub flags: Field<u32>,
}

impl Segment {
    pub fn parse_segments(
        buffer: &[u8],
        load_commands: &[LoadCommand],
        endianness: Endianness,
    ) -> Result<Vec<Self>, errors::FileParseError> {
        let mut segments = Vec::new();

        for cmd in load_commands {
            if cmd.cmd.value == 0x1 /* LC_SEGMENT */ || cmd.cmd.value == 0x19
            /* LC_SEGMENT_64 */
            {
                let offset = cmd.cmd.offset;
                let name = String::from_utf8_lossy(&buffer[offset + 8..offset + 24])
                    .trim_end_matches('\0')
                    .to_string();

                let read_u32 = |off: usize| -> Result<u32, errors::FileParseError> {
                    let bytes: [u8; 4] = buffer
                        .get(off..off + 4)
                        .ok_or(errors::FileParseError::BufferOverflow)?
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?;
                    Ok(match endianness {
                        Endianness::Little => u32::from_le_bytes(bytes),
                        Endianness::Big => u32::from_be_bytes(bytes),
                    })
                };

                let read_u64 = |off: usize| -> Result<u64, errors::FileParseError> {
                    let bytes: [u8; 8] = buffer
                        .get(off..off + 8)
                        .ok_or(errors::FileParseError::BufferOverflow)?
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?;
                    Ok(match endianness {
                        Endianness::Little => u64::from_le_bytes(bytes),
                        Endianness::Big => u64::from_be_bytes(bytes),
                    })
                };

                let vmaddr = Field::new(read_u64(offset + 24)?, offset + 24, 8);
                let vmsize = Field::new(read_u64(offset + 32)?, offset + 32, 8);
                let fileoff = Field::new(read_u64(offset + 40)?, offset + 40, 8);
                let filesize = Field::new(read_u64(offset + 48)?, offset + 48, 8);
                let maxprot = Field::new(read_u32(offset + 56)?, offset + 56, 4);
                let initprot = Field::new(read_u32(offset + 60)?, offset + 60, 4);
                let nsects = Field::new(read_u32(offset + 64)?, offset + 64, 4);
                let flags = Field::new(read_u32(offset + 68)?, offset + 68, 4);

                segments.push(Segment {
                    name,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    nsects,
                    flags,
                });
            }
        }

        Ok(segments)
    }
}
