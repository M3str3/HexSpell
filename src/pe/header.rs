//! Definitions for the various headers that make up a PE file.
//!
//! The structs in this module map directly onto the layout described in
//! Microsoft's PE/COFF specification. Each numeric field is represented
//! as a [`Field`] so it can be patched without
//! recalculating offsets manually.

use core::fmt;

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32, extract_u64};

/// PE optional header magic: `0x10B` (PE32).
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum PEType {
    /// 32-bit optional header (`IMAGE_NT_OPTIONAL_HDR32_MAGIC`).
    PE32,
    /// 64-bit optional header (`IMAGE_NT_OPTIONAL_HDR64_MAGIC`).
    PE32Plus,
}

/// Preferred load address as stored in the optional header (4 or 8 bytes on disk).
#[derive(Clone, Copy)]
pub enum ImageBase {
    /// PE32 image base (`u32`).
    Base32(u32),
    /// PE32+ image base (`u64`).
    Base64(u64),
}

/// Stack/heap reserve or commit size (4 bytes in PE32, 8 bytes in PE32+).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SizedU64 {
    /// PE32 on-disk width (`u32`).
    U32(u32),
    /// PE32+ on-disk width (`u64`).
    U64(u64),
}

/// `IMAGE_DATA_DIRECTORY` — RVA and size of a data table.
pub struct DataDirectoryEntry {
    /// RVA of the directory (`VirtualAddress`).
    pub virtual_address: Field<u32>,
    /// Size of the directory in bytes.
    pub size: Field<u32>,
}

/// Data directory index (`IMAGE_DIRECTORY_ENTRY_*`).
pub const EXPORT: usize = 0;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_IMPORT`).
pub const IMPORT: usize = 1;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_RESOURCE`).
pub const RESOURCE: usize = 2;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`).
pub const EXCEPTION: usize = 3;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_SECURITY`).
pub const SECURITY: usize = 4;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_BASERELOC`).
pub const BASERELOC: usize = 5;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_DEBUG`).
pub const DEBUG: usize = 6;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_ARCHITECTURE`).
pub const ARCHITECTURE: usize = 7;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_GLOBALPTR`).
pub const GLOBAL_PTR: usize = 8;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_TLS`).
pub const TLS: usize = 9;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`).
pub const LOAD_CONFIG: usize = 10;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`).
pub const BOUND_IMPORT: usize = 11;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_IAT`).
pub const IAT: usize = 12;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`).
pub const DELAY_IMPORT: usize = 13;
/// Data directory index (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`).
pub const COM_DESCRIPTOR: usize = 14;

/// Target CPU derived from the COFF `machine` field.
pub enum Architecture {
    /// `IMAGE_FILE_MACHINE_I386` (`0x014c`).
    X86,
    /// `IMAGE_FILE_MACHINE_AMD64` (`0x8664`).
    X64,
    /// `IMAGE_FILE_MACHINE_ARMNT` (`0x01c4`) — ARM32 / CHPE.
    Armnt,
    /// `IMAGE_FILE_MACHINE_ARM64` (`0xAA64`).
    Arm64,
    /// `IMAGE_FILE_MACHINE_ARM64X` (`0xA64E`) — ARM64X hybrid.
    Arm64x,
    /// Any other machine value.
    Unknown,
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::Armnt => "armnt",
            Architecture::Arm64 => "arm64",
            Architecture::Arm64x => "arm64x",
            Architecture::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl Architecture {
    /// Maps a COFF `machine` constant to [`Architecture`].
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x014c => Architecture::X86,
            0x8664 => Architecture::X64,
            0x01c4 => Architecture::Armnt,
            0xAA64 => Architecture::Arm64,
            0xA64E => Architecture::Arm64x,
            _ => Architecture::Unknown,
        }
    }
}

/// Optional header fields (PE32 / PE32+).
///
/// Field offsets follow the Microsoft PE/COFF specification. `base_of_data` is present only for
/// PE32; `image_base` is 4 bytes wide for PE32 and 8 bytes for PE32+.
pub struct OptionalHeader {
    /// `Magic` — `0x10B` (PE32) or `0x20B` (PE32+).
    pub magic: Field<u16>,
    /// Linker major version.
    pub major_linker_version: Field<u8>,
    /// Linker minor version.
    pub minor_linker_version: Field<u8>,
    /// Combined size of all code sections.
    pub size_of_code: Field<u32>,
    /// Combined size of initialized data sections.
    pub size_of_initialized_data: Field<u32>,
    /// Combined size of uninitialized data sections.
    pub size_of_uninitialized_data: Field<u32>,
    /// Relative virtual address of the entry point.
    pub entry_point: Field<u32>,
    /// RVA of the start of the code section.
    pub base_of_code: Field<u32>,
    /// RVA of the start of the data section (PE32 only).
    pub base_of_data: Option<Field<u32>>,
    /// Preferred image load address.
    pub image_base: Field<ImageBase>,
    /// Section alignment in memory.
    pub section_alignment: Field<u32>,
    /// File alignment for raw section data.
    pub file_alignment: Field<u32>,
    /// Required OS major version.
    pub major_operating_system_version: Field<u16>,
    /// Required OS minor version.
    pub minor_operating_system_version: Field<u16>,
    /// Image major version.
    pub major_image_version: Field<u16>,
    /// Image minor version.
    pub minor_image_version: Field<u16>,
    /// Subsystem major version.
    pub major_subsystem_version: Field<u16>,
    /// Subsystem minor version.
    pub minor_subsystem_version: Field<u16>,
    /// Reserved; must be zero.
    pub win32_version_value: Field<u32>,
    /// Size of the image in memory.
    pub size_of_image: Field<u32>,
    /// Combined size of headers and section table.
    pub size_of_headers: Field<u32>,
    /// PE checksum (see [`crate::pe::PE::calc_checksum`]).
    pub checksum: Field<u32>,
    /// Subsystem (`IMAGE_SUBSYSTEM_*`).
    pub subsystem: Field<u16>,
    /// DLL characteristics flags.
    pub dll_characteristics: Field<u16>,
    /// Default stack reserve (4 or 8 bytes on disk).
    pub size_of_stack_reserve: Field<SizedU64>,
    /// Default stack commit (4 or 8 bytes on disk).
    pub size_of_stack_commit: Field<SizedU64>,
    /// Default heap reserve (4 or 8 bytes on disk).
    pub size_of_heap_reserve: Field<SizedU64>,
    /// Default heap commit (4 or 8 bytes on disk).
    pub size_of_heap_commit: Field<SizedU64>,
    /// Loader flags; must be zero.
    pub loader_flags: Field<u32>,
    /// Number of data directory entries (typically 16).
    pub number_of_rva_and_sizes: Field<u32>,
    /// Data directory table (`IMAGE_DATA_DIRECTORY[16]`).
    pub data_directories: [DataDirectoryEntry; 16],
}

impl DataDirectoryEntry {
    /// Parses an `IMAGE_DATA_DIRECTORY` at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        Ok(DataDirectoryEntry {
            virtual_address: Field::new(extract_u32(buffer, offset)?, offset, 4),
            size: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
        })
    }
}

impl OptionalHeader {
    /// Parses the optional header at `offset` (PE32 or PE32+).
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        let magic = extract_u16(buffer, offset)?;
        let pe_type = match magic {
            0x10B => PEType::PE32,
            0x20B => PEType::PE32Plus,
            _ => return Err(FileParseError::InvalidFileFormat),
        };

        let extract_u8 = |buf: &[u8], off: usize| -> Result<u8, FileParseError> {
            buf.get(off).copied().ok_or(FileParseError::BufferOverflow)
        };

        let parse_sized_u64 =
            |buf: &[u8], off: usize, size: usize| -> Result<SizedU64, FileParseError> {
                match size {
                    4 => Ok(SizedU64::U32(extract_u32(buf, off)?)),
                    8 => Ok(SizedU64::U64(extract_u64(buf, off)?)),
                    _ => Err(FileParseError::InvalidFileFormat),
                }
            };

        let (
            image_base,
            base_of_data,
            stack_size,
            heap_size,
            loader_flags_off,
            number_of_rva_off,
            data_dirs_off,
        ) = match pe_type {
            PEType::PE32 => (
                Field::new(
                    ImageBase::Base32(extract_u32(buffer, offset + 28)?),
                    offset + 28,
                    4,
                ),
                Some(Field::new(
                    extract_u32(buffer, offset + 24)?,
                    offset + 24,
                    4,
                )),
                4usize,
                4usize,
                offset + 88,
                offset + 92,
                offset + 96,
            ),
            PEType::PE32Plus => (
                Field::new(
                    ImageBase::Base64(extract_u64(buffer, offset + 24)?),
                    offset + 24,
                    8,
                ),
                None,
                8usize,
                8usize,
                offset + 104,
                offset + 108,
                offset + 112,
            ),
        };

        let stack_reserve_off = offset + 72;
        let stack_commit_off = stack_reserve_off + stack_size;
        let heap_reserve_off = stack_commit_off + stack_size;
        let heap_commit_off = heap_reserve_off + heap_size;

        let number_of_rva_and_sizes = extract_u32(buffer, number_of_rva_off)?;
        let active_directories = (number_of_rva_and_sizes as usize).min(16);
        let min_end = data_dirs_off + active_directories * 8;
        if buffer.len() < min_end {
            return Err(FileParseError::BufferOverflow);
        }

        let mut data_directories: [DataDirectoryEntry; 16] =
            std::array::from_fn(|i| DataDirectoryEntry {
                virtual_address: Field::new(0, data_dirs_off + i * 8, 4),
                size: Field::new(0, data_dirs_off + i * 8 + 4, 4),
            });
        for i in 0..active_directories {
            data_directories[i] = DataDirectoryEntry::parse(buffer, data_dirs_off + i * 8)?;
        }

        Ok(OptionalHeader {
            magic: Field::new(magic, offset, 2),
            major_linker_version: Field::new(extract_u8(buffer, offset + 2)?, offset + 2, 1),
            minor_linker_version: Field::new(extract_u8(buffer, offset + 3)?, offset + 3, 1),
            size_of_code: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            size_of_initialized_data: Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4),
            size_of_uninitialized_data: Field::new(
                extract_u32(buffer, offset + 12)?,
                offset + 12,
                4,
            ),
            entry_point: Field::new(extract_u32(buffer, offset + 16)?, offset + 16, 4),
            base_of_code: Field::new(extract_u32(buffer, offset + 20)?, offset + 20, 4),
            base_of_data,
            image_base,
            section_alignment: Field::new(extract_u32(buffer, offset + 32)?, offset + 32, 4),
            file_alignment: Field::new(extract_u32(buffer, offset + 36)?, offset + 36, 4),
            major_operating_system_version: Field::new(
                extract_u16(buffer, offset + 40)?,
                offset + 40,
                2,
            ),
            minor_operating_system_version: Field::new(
                extract_u16(buffer, offset + 42)?,
                offset + 42,
                2,
            ),
            major_image_version: Field::new(extract_u16(buffer, offset + 44)?, offset + 44, 2),
            minor_image_version: Field::new(extract_u16(buffer, offset + 46)?, offset + 46, 2),
            major_subsystem_version: Field::new(extract_u16(buffer, offset + 48)?, offset + 48, 2),
            minor_subsystem_version: Field::new(extract_u16(buffer, offset + 50)?, offset + 50, 2),
            win32_version_value: Field::new(extract_u32(buffer, offset + 52)?, offset + 52, 4),
            size_of_image: Field::new(extract_u32(buffer, offset + 56)?, offset + 56, 4),
            size_of_headers: Field::new(extract_u32(buffer, offset + 60)?, offset + 60, 4),
            checksum: Field::new(extract_u32(buffer, offset + 64)?, offset + 64, 4),
            subsystem: Field::new(extract_u16(buffer, offset + 68)?, offset + 68, 2),
            dll_characteristics: Field::new(extract_u16(buffer, offset + 70)?, offset + 70, 2),
            size_of_stack_reserve: Field::new(
                parse_sized_u64(buffer, stack_reserve_off, stack_size)?,
                stack_reserve_off,
                stack_size,
            ),
            size_of_stack_commit: Field::new(
                parse_sized_u64(buffer, stack_commit_off, stack_size)?,
                stack_commit_off,
                stack_size,
            ),
            size_of_heap_reserve: Field::new(
                parse_sized_u64(buffer, heap_reserve_off, heap_size)?,
                heap_reserve_off,
                heap_size,
            ),
            size_of_heap_commit: Field::new(
                parse_sized_u64(buffer, heap_commit_off, heap_size)?,
                heap_commit_off,
                heap_size,
            ),
            loader_flags: Field::new(extract_u32(buffer, loader_flags_off)?, loader_flags_off, 4),
            number_of_rva_and_sizes: Field::new(number_of_rva_and_sizes, number_of_rva_off, 4),
            data_directories,
        })
    }

    /// Number of data directory slots present on disk (`min(number_of_rva_and_sizes, 16)`).
    pub fn active_data_directory_count(&self) -> usize {
        (self.number_of_rva_and_sizes.value as usize).min(16)
    }

    /// Returns `true` when `index` is within [`Self::active_data_directory_count`].
    pub fn has_data_directory(&self, index: usize) -> bool {
        index < self.active_data_directory_count()
    }

    /// Returns [`PEType`] from the optional header `magic` field.
    pub fn pe_type(&self) -> Result<PEType, FileParseError> {
        match self.magic.value {
            0x10B => Ok(PEType::PE32),
            0x20B => Ok(PEType::PE32Plus),
            _ => Err(FileParseError::InvalidFileFormat),
        }
    }
}

impl Field<ImageBase> {
    /// Updates the image base in the PE optional header (always little-endian).
    pub fn update(
        &mut self,
        buffer: &mut [u8],
        new_value: ImageBase,
    ) -> Result<(), FileParseError> {
        match (new_value, self.size) {
            (ImageBase::Base32(value), 4) => {
                buffer[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());
                self.value = new_value;
                Ok(())
            }
            (ImageBase::Base64(value), 8) => {
                buffer[self.offset..self.offset + 8].copy_from_slice(&value.to_le_bytes());
                self.value = new_value;
                Ok(())
            }
            _ => Err(FileParseError::InvalidFileFormat),
        }
    }
}

impl Field<SizedU64> {
    /// Updates a stack/heap size field (4 bytes for PE32, 8 for PE32+).
    pub fn update(&mut self, buffer: &mut [u8], new_value: SizedU64) -> Result<(), FileParseError> {
        match (new_value, self.size) {
            (SizedU64::U32(value), 4) => {
                buffer[self.offset..self.offset + 4].copy_from_slice(&value.to_le_bytes());
                self.value = new_value;
                Ok(())
            }
            (SizedU64::U64(value), 8) => {
                buffer[self.offset..self.offset + 8].copy_from_slice(&value.to_le_bytes());
                self.value = new_value;
                Ok(())
            }
            _ => Err(FileParseError::InvalidFileFormat),
        }
    }
}
