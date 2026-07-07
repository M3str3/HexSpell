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

impl FatArch {
    /// Byte range `(start, end)` of this slice inside a FAT file.
    pub fn byte_range(&self) -> Result<(usize, usize), FileParseError> {
        let start = self.offset as usize;
        let end = start
            .checked_add(self.size as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        Ok((start, end))
    }
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

    /// Returns a sub-slice of `buffer` for `arch` without copying.
    pub fn slice_ref<'a>(
        &self,
        buffer: &'a [u8],
        arch: &FatArch,
    ) -> Result<&'a [u8], FileParseError> {
        let (start, end) = arch.byte_range()?;
        buffer.get(start..end).ok_or(FileParseError::BufferOverflow)
    }

    /// Copies the thin Mach-O bytes for `arch` out of `buffer`.
    pub fn slice_bytes(&self, buffer: &[u8], arch: &FatArch) -> Result<Vec<u8>, FileParseError> {
        Ok(self.slice_ref(buffer, arch)?.to_vec())
    }

    /// Builds a FAT binary from thin Mach-O slices.
    ///
    /// Each tuple is `(arch metadata, thin Mach-O bytes)`. Offsets are assigned sequentially with
    /// the alignment given by `FatArch::align`.
    pub fn build(slices: &[(FatArch, &[u8])]) -> Result<Vec<u8>, FileParseError> {
        if slices.is_empty() {
            return Err(FileParseError::InvalidFileFormat);
        }
        let is_64 = slices
            .iter()
            .any(|(_, data)| data.len() > u32::MAX as usize);
        let arch_size = if is_64 { 32 } else { 20 };
        let header_size = 8 + arch_size * slices.len();

        let mut arches = Vec::with_capacity(slices.len());
        let mut cursor = header_size;
        for (template, data) in slices {
            let align = 1usize << template.align.min(31);
            cursor = align_up(cursor, align);
            arches.push(FatArch {
                cpu_type: template.cpu_type,
                cpu_subtype: template.cpu_subtype,
                offset: cursor as u64,
                size: data.len() as u64,
                align: template.align,
            });
            cursor += data.len();
        }

        let total_size = cursor;
        let mut out = vec![0u8; total_size];
        let order = ByteOrder::Big;
        let magic = if is_64 { 0xCAFE_BABF } else { 0xCAFE_BABE };
        order.write_u32(&mut out, 0, magic);
        order.write_u32(&mut out, 4, arches.len() as u32);

        for (i, arch) in arches.iter().enumerate() {
            let base = 8 + i * arch_size;
            order.write_u32(&mut out, base, arch.cpu_type);
            order.write_u32(&mut out, base + 4, arch.cpu_subtype);
            if is_64 {
                order.write_u64(&mut out, base + 8, arch.offset);
                order.write_u64(&mut out, base + 16, arch.size);
                order.write_u32(&mut out, base + 24, arch.align);
            } else {
                order.write_u32(&mut out, base + 8, arch.offset as u32);
                order.write_u32(&mut out, base + 12, arch.size as u32);
                order.write_u32(&mut out, base + 16, arch.align);
            }
        }

        for (arch, data) in arches.iter().zip(slices.iter().map(|(_, d)| *d)) {
            let start = arch.offset as usize;
            out[start..start + data.len()].copy_from_slice(data);
        }

        Ok(out)
    }

    /// Merges a new thin slice into an existing FAT binary (or creates a new FAT when `fat` is thin).
    pub fn merge(
        fat_buffer: &[u8],
        new_arch: FatArch,
        new_data: &[u8],
    ) -> Result<Vec<u8>, FileParseError> {
        let mut slices: Vec<(FatArch, Vec<u8>)> = if let Some(existing) = Self::parse(fat_buffer)? {
            existing
                .arches
                .iter()
                .map(|a| Ok((a.clone(), existing.slice_bytes(fat_buffer, a)?)))
                .collect::<Result<Vec<_>, FileParseError>>()?
        } else {
            vec![(
                FatArch {
                    cpu_type: 0,
                    cpu_subtype: 0,
                    offset: 0,
                    size: fat_buffer.len() as u64,
                    align: 0,
                },
                fat_buffer.to_vec(),
            )]
        };

        slices.push((new_arch, new_data.to_vec()));
        let refs: Vec<(FatArch, &[u8])> = slices
            .iter()
            .map(|(a, d)| (a.clone(), d.as_slice()))
            .collect();
        Self::build(&refs)
    }
}

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}
