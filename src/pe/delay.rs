//! Delay-load import descriptors (`ImgDelayDescr` / `IMAGE_DELAYLOAD_DESCRIPTOR`).
//!
//! Each descriptor references the delay-loaded DLL name, IAT, INT, and optional
//! bound/unload IAT tables by RVA.

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::header::PEType;
use crate::pe::import::{parse_thunk_table, ImportEntry};
use crate::pe::section::PeSection;
use crate::utils::extract_u32;

/// `IMAGE_DELAYLOAD_DESCRIPTOR` — 32 bytes (`ImgDelayDescr`).
pub struct DelayLoadDescriptor {
    /// Attribute flags (`dlattrRva` etc.).
    pub attributes: Field<u32>,
    /// RVA of the delay-loaded DLL name string.
    pub dll_name_rva: Field<u32>,
    /// RVA of the module handle storage.
    pub module_handle_rva: Field<u32>,
    /// RVA of the delay-load IAT.
    pub delay_import_address_table_rva: Field<u32>,
    /// RVA of the delay-load INT (hint/name table).
    pub delay_import_name_table_rva: Field<u32>,
    /// RVA of the bound delay-load IAT.
    pub bound_delay_import_table_rva: Field<u32>,
    /// RVA of the unload delay-load IAT.
    pub unload_delay_import_table_rva: Field<u32>,
    /// Timestamp of the target DLL when bound.
    pub time_date_stamp: Field<u32>,
}

/// Resolved delay-load import from one descriptor.
pub struct DelayLoadImport {
    /// On-disk descriptor fields.
    pub descriptor: DelayLoadDescriptor,
    /// Absolute file offset of the DLL name string.
    pub dll_name_offset: usize,
    /// Decoded DLL name.
    pub dll_name: String,
    /// Entries from the delay-load INT.
    pub entries: Vec<ImportEntry>,
}

/// Parsed delay-load import directory.
pub struct DelayLoadDirectory {
    /// Absolute file offset where the descriptor array starts.
    pub offset: usize,
    /// Parsed descriptors (null terminator excluded).
    pub descriptors: Vec<DelayLoadDescriptor>,
    /// Resolved delay-load imports.
    pub dlls: Vec<DelayLoadImport>,
}

impl DelayLoadDescriptor {
    /// Size of `IMAGE_DELAYLOAD_DESCRIPTOR` in bytes.
    pub const SIZE: usize = 32;

    /// Parses one descriptor at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(DelayLoadDescriptor {
            attributes: Field::new(extract_u32(buffer, offset)?, offset, 4),
            dll_name_rva: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            module_handle_rva: Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4),
            delay_import_address_table_rva: Field::new(
                extract_u32(buffer, offset + 12)?,
                offset + 12,
                4,
            ),
            delay_import_name_table_rva: Field::new(
                extract_u32(buffer, offset + 16)?,
                offset + 16,
                4,
            ),
            bound_delay_import_table_rva: Field::new(
                extract_u32(buffer, offset + 20)?,
                offset + 20,
                4,
            ),
            unload_delay_import_table_rva: Field::new(
                extract_u32(buffer, offset + 24)?,
                offset + 24,
                4,
            ),
            time_date_stamp: Field::new(extract_u32(buffer, offset + 28)?, offset + 28, 4),
        })
    }

    /// `true` when all RVAs and fields are zero (end of descriptor array).
    pub fn is_null(&self) -> bool {
        self.attributes.value == 0
            && self.dll_name_rva.value == 0
            && self.module_handle_rva.value == 0
            && self.delay_import_address_table_rva.value == 0
            && self.delay_import_name_table_rva.value == 0
            && self.bound_delay_import_table_rva.value == 0
            && self.unload_delay_import_table_rva.value == 0
            && self.time_date_stamp.value == 0
    }
}

impl DelayLoadDirectory {
    /// Parses the delay-load directory from `buffer`.
    pub fn parse(
        buffer: &[u8],
        sections: &[PeSection],
        delay_rva: u32,
        pe_type: PEType,
    ) -> Result<Self, FileParseError> {
        if delay_rva == 0 {
            return Ok(DelayLoadDirectory {
                offset: 0,
                descriptors: Vec::new(),
                dlls: Vec::new(),
            });
        }

        let offset = crate::pe::import::rva_to_offset(buffer, sections, delay_rva)?;
        let mut descriptors = Vec::new();
        let mut cursor = offset;

        loop {
            let desc = DelayLoadDescriptor::parse(buffer, cursor)?;
            if desc.is_null() {
                break;
            }
            descriptors.push(desc);
            cursor += DelayLoadDescriptor::SIZE;
        }

        let dlls = descriptors
            .iter()
            .map(|desc| parse_delay_dll(buffer, sections, desc, pe_type))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(DelayLoadDirectory {
            offset,
            descriptors,
            dlls,
        })
    }
}

fn parse_delay_dll(
    buffer: &[u8],
    sections: &[PeSection],
    desc: &DelayLoadDescriptor,
    pe_type: PEType,
) -> Result<DelayLoadImport, FileParseError> {
    let dll_name_offset =
        crate::pe::import::rva_to_offset(buffer, sections, desc.dll_name_rva.value)?;
    let dll_name = read_c_string(buffer, dll_name_offset)?;

    let thunk_rva = if desc.delay_import_name_table_rva.value != 0 {
        desc.delay_import_name_table_rva.value
    } else {
        desc.delay_import_address_table_rva.value
    };

    let entries = parse_thunk_table(buffer, sections, thunk_rva, pe_type)?;

    Ok(DelayLoadImport {
        descriptor: DelayLoadDescriptor {
            attributes: desc.attributes.clone(),
            dll_name_rva: desc.dll_name_rva.clone(),
            module_handle_rva: desc.module_handle_rva.clone(),
            delay_import_address_table_rva: desc.delay_import_address_table_rva.clone(),
            delay_import_name_table_rva: desc.delay_import_name_table_rva.clone(),
            bound_delay_import_table_rva: desc.bound_delay_import_table_rva.clone(),
            unload_delay_import_table_rva: desc.unload_delay_import_table_rva.clone(),
            time_date_stamp: desc.time_date_stamp.clone(),
        },
        dll_name_offset,
        dll_name,
        entries,
    })
}

fn read_c_string(buffer: &[u8], offset: usize) -> Result<String, FileParseError> {
    let tail = buffer.get(offset..).ok_or(FileParseError::BufferOverflow)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(FileParseError::InvalidFileFormat)?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

// Re-export parse_thunk_table for delay module — it's private in import.rs
// We'll make parse_thunk_table pub(crate) in import.rs
