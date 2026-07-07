//! CLR / .NET metadata directory (`IMAGE_COR20_HEADER`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::header::DataDirectoryEntry;
use crate::utils::{extract_u16, extract_u32};

/// Minimum size of `IMAGE_COR20_HEADER`.
pub const COR20_HEADER_SIZE: usize = 72;

/// `COMIMAGE_FLAGS_ILONLY`.
pub const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;

/// `IMAGE_COR20_HEADER` base fields.
pub struct Cor20Header {
    /// Size of this structure (`cb`).
    pub cb: Field<u32>,
    /// Major runtime version.
    pub major_runtime_version: Field<u16>,
    /// Minor runtime version.
    pub minor_runtime_version: Field<u16>,
    /// Metadata directory (`MetaData`).
    pub metadata: DataDirectoryEntry,
    /// Image flags (`Flags`).
    pub flags: Field<u32>,
    /// Entry point token or RVA (`EntryPointToken`).
    pub entry_point_token: Field<u32>,
    /// Resources directory (`Resources`).
    pub resources: DataDirectoryEntry,
    /// Strong name signature directory (`StrongNameSignature`).
    pub strong_name_signature: DataDirectoryEntry,
    /// Code manager table directory (`CodeManagerTable`).
    pub code_manager_table: DataDirectoryEntry,
    /// VTable fixups directory (`VTableFixups`).
    pub vtable_fixups: DataDirectoryEntry,
    /// Export address table jumps directory (`ExportAddressTableJumps`).
    pub export_address_table_jumps: DataDirectoryEntry,
    /// Managed native header directory (`ManagedNativeHeader`).
    pub managed_native_header: DataDirectoryEntry,
}

impl Cor20Header {
    /// Parses `IMAGE_COR20_HEADER` at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        let cb = extract_u32(buffer, offset)?;
        if cb < COR20_HEADER_SIZE as u32 {
            return Err(FileParseError::InvalidFileFormat);
        }
        if buffer.len() < offset + cb as usize {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(Cor20Header {
            cb: Field::new(cb, offset, 4),
            major_runtime_version: Field::new(extract_u16(buffer, offset + 4)?, offset + 4, 2),
            minor_runtime_version: Field::new(extract_u16(buffer, offset + 6)?, offset + 6, 2),
            metadata: DataDirectoryEntry::parse(buffer, offset + 8)?,
            flags: Field::new(extract_u32(buffer, offset + 16)?, offset + 16, 4),
            entry_point_token: Field::new(extract_u32(buffer, offset + 20)?, offset + 20, 4),
            resources: DataDirectoryEntry::parse(buffer, offset + 24)?,
            strong_name_signature: DataDirectoryEntry::parse(buffer, offset + 32)?,
            code_manager_table: DataDirectoryEntry::parse(buffer, offset + 40)?,
            vtable_fixups: DataDirectoryEntry::parse(buffer, offset + 48)?,
            export_address_table_jumps: DataDirectoryEntry::parse(buffer, offset + 56)?,
            managed_native_header: DataDirectoryEntry::parse(buffer, offset + 64)?,
        })
    }

    /// Returns `true` when the image is IL-only (`COMIMAGE_FLAGS_ILONLY`).
    pub fn is_il_only(&self) -> bool {
        self.flags.value & COMIMAGE_FLAGS_ILONLY != 0
    }
}
