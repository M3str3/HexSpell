//! Bound import directory (`IMAGE_BOUND_IMPORT_DESCRIPTOR`).
//!
//! The bound import data directory points at an array of descriptors. Module
//! name offsets are relative to the start of the bound import table, not RVAs.

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::section::PeSection;
use crate::utils::{extract_u16, extract_u32};

/// `IMAGE_BOUND_FORWARDER_REF` — 8 bytes.
pub struct BoundForwarderRef {
    /// Bound timestamp of the forwarded module.
    pub time_date_stamp: Field<u32>,
    /// Offset of the forwarded module name from the bound import table base.
    pub offset_module_name: Field<u16>,
    /// Reserved; must be zero.
    pub reserved: Field<u16>,
}

/// `IMAGE_BOUND_IMPORT_DESCRIPTOR` — 8 bytes.
pub struct BoundImportDescriptor {
    /// Bound timestamp of the imported module.
    pub time_date_stamp: Field<u32>,
    /// Offset of the module name from the bound import table base.
    pub offset_module_name: Field<u16>,
    /// Number of `IMAGE_BOUND_FORWARDER_REF` records following this descriptor.
    pub number_of_module_forwarder_refs: Field<u16>,
}

/// One bound import module with optional forwarder refs.
pub struct BoundImportModule {
    /// On-disk descriptor fields.
    pub descriptor: BoundImportDescriptor,
    /// Decoded DLL name.
    pub module_name: String,
    /// Forwarder reference records when `number_of_module_forwarder_refs` is non-zero.
    pub forwarder_refs: Vec<BoundForwarderRef>,
}

/// Parsed bound import directory.
pub struct BoundImportDirectory {
    /// Absolute file offset of the descriptor array.
    pub offset: usize,
    /// Bound import modules (null terminator excluded).
    pub modules: Vec<BoundImportModule>,
}

impl BoundForwarderRef {
    /// Size of `IMAGE_BOUND_FORWARDER_REF` in bytes.
    pub const SIZE: usize = 8;

    /// Parses one forwarder ref at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(BoundForwarderRef {
            time_date_stamp: Field::new(extract_u32(buffer, offset)?, offset, 4),
            offset_module_name: Field::new(extract_u16(buffer, offset + 4)?, offset + 4, 2),
            reserved: Field::new(extract_u16(buffer, offset + 6)?, offset + 6, 2),
        })
    }
}

impl BoundImportDescriptor {
    /// Size of `IMAGE_BOUND_IMPORT_DESCRIPTOR` in bytes.
    pub const SIZE: usize = 8;

    /// Parses one descriptor at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(BoundImportDescriptor {
            time_date_stamp: Field::new(extract_u32(buffer, offset)?, offset, 4),
            offset_module_name: Field::new(extract_u16(buffer, offset + 4)?, offset + 4, 2),
            number_of_module_forwarder_refs: Field::new(
                extract_u16(buffer, offset + 6)?,
                offset + 6,
                2,
            ),
        })
    }

    /// `true` when all fields are zero (end of descriptor array).
    pub fn is_null(&self) -> bool {
        self.time_date_stamp.value == 0
            && self.offset_module_name.value == 0
            && self.number_of_module_forwarder_refs.value == 0
    }
}

impl BoundImportDirectory {
    /// Parses the bound import directory from `buffer`.
    pub fn parse(
        buffer: &[u8],
        sections: &[PeSection],
        bound_rva: u32,
    ) -> Result<Self, FileParseError> {
        if bound_rva == 0 {
            return Ok(BoundImportDirectory {
                offset: 0,
                modules: Vec::new(),
            });
        }

        let offset = crate::pe::import::rva_to_offset(buffer, sections, bound_rva)?;
        let mut modules = Vec::new();
        let mut cursor = offset;

        loop {
            if buffer.len() < cursor + BoundImportDescriptor::SIZE {
                return Err(FileParseError::BufferOverflow);
            }

            let descriptor = BoundImportDescriptor::parse(buffer, cursor)?;
            if descriptor.is_null() {
                break;
            }

            let module_name = read_name(buffer, offset, descriptor.offset_module_name.value)?;
            cursor += BoundImportDescriptor::SIZE;

            let mut forwarder_refs = Vec::new();
            for _ in 0..descriptor.number_of_module_forwarder_refs.value {
                forwarder_refs.push(BoundForwarderRef::parse(buffer, cursor)?);
                cursor += BoundForwarderRef::SIZE;
            }

            modules.push(BoundImportModule {
                descriptor,
                module_name,
                forwarder_refs,
            });
        }

        Ok(BoundImportDirectory { offset, modules })
    }
}

fn read_name(buffer: &[u8], table_base: usize, name_offset: u16) -> Result<String, FileParseError> {
    let off = table_base
        .checked_add(name_offset as usize)
        .ok_or(FileParseError::BufferOverflow)?;
    let tail = buffer.get(off..).ok_or(FileParseError::BufferOverflow)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(FileParseError::InvalidFileFormat)?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}
