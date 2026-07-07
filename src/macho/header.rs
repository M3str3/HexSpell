//! Core structures describing the Mach-O header.

use crate::errors;
use crate::field::{ByteOrder, Field};

/// Mach-O header (`mach_header` / `mach_header_64`).
///
/// `magic` holds the normalized constant (`0xFEEDFACE`, etc.). For byte order, use
/// [`crate::macho::MachO::byte_order`] or [`ByteOrder::from_macho_header_bytes`] on the raw buffer.
#[derive(Debug)]
pub struct MachHeader {
    /// Magic number identifying word size and endianness.
    pub magic: Field<u32>,
    pub cpu_type: Field<u32>,
    pub cpu_subtype: Field<u32>,
    pub file_type: Field<u32>,
    /// Number of load commands.
    pub ncmds: Field<u32>,
    /// Total size of all load commands.
    pub sizeofcmds: Field<u32>,
    pub flags: Field<u32>,
    /// Present only in 64-bit headers (`reserved`).
    pub reserved: Option<Field<u32>>,
}

impl MachHeader {
    /// Parses a Mach-O header at the start of `buffer`.
    pub fn parse(
        buffer: &[u8],
        order: ByteOrder,
        is_64bit: bool,
    ) -> Result<Self, errors::FileParseError> {
        let min_len = if is_64bit { 32 } else { 28 };
        if buffer.len() < min_len {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let magic = Field::new(order.read_u32(buffer, 0)?, 0, 4);
        let cpu_type = Field::new(order.read_u32(buffer, 4)?, 4, 4);
        let cpu_subtype = Field::new(order.read_u32(buffer, 8)?, 8, 4);
        let file_type = Field::new(order.read_u32(buffer, 12)?, 12, 4);
        let ncmds = Field::new(order.read_u32(buffer, 16)?, 16, 4);
        let sizeofcmds = Field::new(order.read_u32(buffer, 20)?, 20, 4);
        let flags = Field::new(order.read_u32(buffer, 24)?, 24, 4);

        let reserved = if is_64bit {
            Some(Field::new(order.read_u32(buffer, 28)?, 28, 4))
        } else {
            None
        };

        Ok(MachHeader {
            magic,
            cpu_type,
            cpu_subtype,
            file_type,
            ncmds,
            sizeofcmds,
            flags,
            reserved,
        })
    }
}
