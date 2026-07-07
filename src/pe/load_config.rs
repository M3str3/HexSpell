//! Load configuration directory (`IMAGE_LOAD_CONFIG_DIRECTORY`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::header::PEType;
use crate::utils::{extract_u16, extract_u32, extract_u64};

/// Base fields of `IMAGE_LOAD_CONFIG_DIRECTORY32` / `IMAGE_LOAD_CONFIG_DIRECTORY64`.
pub struct LoadConfigDirectory {
    /// Size of this structure (`Size`).
    pub size: Field<u32>,
    /// Time/date stamp.
    pub time_date_stamp: Field<u32>,
    /// Major version.
    pub major_version: Field<u16>,
    /// Minor version.
    pub minor_version: Field<u16>,
    /// Global flags clear mask.
    pub global_flags_clear: Field<u32>,
    /// Global flags set mask.
    pub global_flags_set: Field<u32>,
    /// Critical section default timeout.
    pub critical_section_default_timeout: Field<u32>,
    /// De-commit free block threshold (4 or 8 bytes on disk).
    pub de_commit_free_block_threshold: Field<u64>,
    /// De-commit total free threshold (4 or 8 bytes on disk).
    pub de_commit_total_free_threshold: Field<u64>,
    /// Lock prefix table VA.
    pub lock_prefix_table: Field<u64>,
    /// Maximum allocation size (4 or 8 bytes on disk).
    pub maximum_allocation_size: Field<u64>,
    /// Virtual memory threshold (4 or 8 bytes on disk).
    pub virtual_memory_threshold: Field<u64>,
    /// Process affinity mask (PE32+ only).
    pub process_affinity_mask: Option<Field<u64>>,
    /// Process heap flags.
    pub process_heap_flags: Field<u32>,
    /// CSD version.
    pub csd_version: Field<u16>,
    /// Reserved fields.
    pub reserved1: Field<u16>,
    /// Reserved fields.
    pub reserved2: Field<u32>,
    /// Security cookie VA.
    pub security_cookie: Field<u64>,
}

impl LoadConfigDirectory {
    /// Parses the load configuration directory at `offset`.
    pub fn parse(buffer: &[u8], offset: usize, pe_type: PEType) -> Result<Self, FileParseError> {
        let size = extract_u32(buffer, offset)?;
        if size < 64 {
            return Err(FileParseError::InvalidFileFormat);
        }
        if buffer.len() < offset + size as usize {
            return Err(FileParseError::BufferOverflow);
        }

        match pe_type {
            PEType::PE32 => {
                let read_u64 = |off: usize| -> Result<u64, FileParseError> {
                    Ok(extract_u32(buffer, off)? as u64)
                };
                Ok(LoadConfigDirectory {
                    size: Field::new(size, offset, 4),
                    time_date_stamp: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
                    major_version: Field::new(extract_u16(buffer, offset + 8)?, offset + 8, 2),
                    minor_version: Field::new(extract_u16(buffer, offset + 10)?, offset + 10, 2),
                    global_flags_clear: Field::new(
                        extract_u32(buffer, offset + 12)?,
                        offset + 12,
                        4,
                    ),
                    global_flags_set: Field::new(extract_u32(buffer, offset + 16)?, offset + 16, 4),
                    critical_section_default_timeout: Field::new(
                        extract_u32(buffer, offset + 20)?,
                        offset + 20,
                        4,
                    ),
                    de_commit_free_block_threshold: Field::new(
                        read_u64(offset + 24)?,
                        offset + 24,
                        4,
                    ),
                    de_commit_total_free_threshold: Field::new(
                        read_u64(offset + 28)?,
                        offset + 28,
                        4,
                    ),
                    lock_prefix_table: Field::new(read_u64(offset + 32)?, offset + 32, 4),
                    maximum_allocation_size: Field::new(read_u64(offset + 36)?, offset + 36, 4),
                    virtual_memory_threshold: Field::new(read_u64(offset + 40)?, offset + 40, 4),
                    process_affinity_mask: None,
                    process_heap_flags: Field::new(
                        extract_u32(buffer, offset + 44)?,
                        offset + 44,
                        4,
                    ),
                    csd_version: Field::new(extract_u16(buffer, offset + 48)?, offset + 48, 2),
                    reserved1: Field::new(extract_u16(buffer, offset + 50)?, offset + 50, 2),
                    reserved2: Field::new(extract_u32(buffer, offset + 52)?, offset + 52, 4),
                    security_cookie: Field::new(read_u64(offset + 56)?, offset + 56, 4),
                })
            }
            PEType::PE32Plus => Ok(LoadConfigDirectory {
                size: Field::new(size, offset, 4),
                time_date_stamp: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
                major_version: Field::new(extract_u16(buffer, offset + 8)?, offset + 8, 2),
                minor_version: Field::new(extract_u16(buffer, offset + 10)?, offset + 10, 2),
                global_flags_clear: Field::new(extract_u32(buffer, offset + 12)?, offset + 12, 4),
                global_flags_set: Field::new(extract_u32(buffer, offset + 16)?, offset + 16, 4),
                critical_section_default_timeout: Field::new(
                    extract_u32(buffer, offset + 20)?,
                    offset + 20,
                    4,
                ),
                de_commit_free_block_threshold: Field::new(
                    extract_u64(buffer, offset + 24)?,
                    offset + 24,
                    8,
                ),
                de_commit_total_free_threshold: Field::new(
                    extract_u64(buffer, offset + 32)?,
                    offset + 32,
                    8,
                ),
                lock_prefix_table: Field::new(extract_u64(buffer, offset + 40)?, offset + 40, 8),
                maximum_allocation_size: Field::new(
                    extract_u64(buffer, offset + 48)?,
                    offset + 48,
                    8,
                ),
                virtual_memory_threshold: Field::new(
                    extract_u64(buffer, offset + 56)?,
                    offset + 56,
                    8,
                ),
                process_affinity_mask: Some(Field::new(
                    extract_u64(buffer, offset + 64)?,
                    offset + 64,
                    8,
                )),
                process_heap_flags: Field::new(extract_u32(buffer, offset + 72)?, offset + 72, 4),
                csd_version: Field::new(extract_u16(buffer, offset + 76)?, offset + 76, 2),
                reserved1: Field::new(extract_u16(buffer, offset + 78)?, offset + 78, 2),
                reserved2: Field::new(extract_u32(buffer, offset + 80)?, offset + 80, 4),
                security_cookie: Field::new(extract_u64(buffer, offset + 84)?, offset + 84, 8),
            }),
        }
    }
}
