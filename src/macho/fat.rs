//! FAT (universal) Mach-O wrapper parsing.
//!
//! A FAT binary begins with a `fat_header` followed by one `fat_arch` (or `fat_arch_64`) per
//! embedded thin Mach-O. HexSpell unpacks a chosen slice into a standalone [`crate::macho::MachO`].

use crate::errors::FileParseError;
use crate::field::ByteOrder;

/// One architecture slice inside a FAT binary (`fat_arch` / `fat_arch_64`).
#[derive(Debug, Clone)]
pub struct FatArch {
    /// CPU type of the slice.
    pub cpu_type: u32,
    /// CPU subtype of the slice.
    pub cpu_subtype: u32,
    /// File offset of the embedded thin Mach-O.
    pub offset: u64,
    /// Size in bytes of the embedded thin Mach-O.
    pub size: u64,
    /// Alignment as a power of two.
    pub align: u32,
}

/// A parsed FAT header plus the list of embedded architecture slices.
#[derive(Debug, Clone)]
pub struct FatHeader {
    /// Byte order the FAT header is stored in (always big-endian in practice).
    pub order: ByteOrder,
    /// `true` for the `fat_arch_64` layout (`0xCAFEBABF`).
    pub is_64: bool,
    /// Architecture slices in file order.
    pub arches: Vec<FatArch>,
}

impl FatHeader {
    /// Detects a FAT magic at the start of `buffer` and, if present, parses the arch table.
    ///
    /// Returns `Ok(None)` when `buffer` is not a FAT binary.
    pub fn parse(buffer: &[u8]) -> Result<Option<Self>, FileParseError> {
        if buffer.len() < 8 {
            return Ok(None);
        }
        let magic_bytes: [u8; 4] = buffer[0..4].try_into().unwrap();
        let magic_be = u32::from_be_bytes(magic_bytes);
        let magic_le = u32::from_le_bytes(magic_bytes);

        let (order, is_64) = match magic_be {
            0xCAFEBABE => (ByteOrder::Big, false),
            0xCAFEBABF => (ByteOrder::Big, true),
            _ => match magic_le {
                0xCAFEBABE => (ByteOrder::Little, false),
                0xCAFEBABF => (ByteOrder::Little, true),
                _ => return Ok(None),
            },
        };

        let nfat_arch = order.read_u32(buffer, 4)? as usize;
        let arch_size = if is_64 { 32 } else { 20 };
        if nfat_arch == 0 || buffer.len() < 8 + arch_size * nfat_arch {
            return Err(FileParseError::BufferOverflow);
        }

        let mut arches = Vec::with_capacity(nfat_arch);
        for i in 0..nfat_arch {
            let base = 8 + i * arch_size;
            let cpu_type = order.read_u32(buffer, base)?;
            let cpu_subtype = order.read_u32(buffer, base + 4)?;
            let (offset, size, align) = if is_64 {
                (
                    order.read_u64(buffer, base + 8)?,
                    order.read_u64(buffer, base + 16)?,
                    order.read_u32(buffer, base + 24)?,
                )
            } else {
                (
                    order.read_u32(buffer, base + 8)? as u64,
                    order.read_u32(buffer, base + 12)? as u64,
                    order.read_u32(buffer, base + 16)?,
                )
            };
            arches.push(FatArch {
                cpu_type,
                cpu_subtype,
                offset,
                size,
                align,
            });
        }

        Ok(Some(FatHeader {
            order,
            is_64,
            arches,
        }))
    }

    /// Copies the thin Mach-O bytes for `arch` out of `buffer`.
    pub fn slice_bytes(&self, buffer: &[u8], arch: &FatArch) -> Result<Vec<u8>, FileParseError> {
        let start = arch.offset as usize;
        let end = start
            .checked_add(arch.size as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        buffer
            .get(start..end)
            .map(|s| s.to_vec())
            .ok_or(FileParseError::BufferOverflow)
    }
}
