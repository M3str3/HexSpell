//! `IMAGE_EXPORT_DIRECTORY` and export table entries.
//!
//! Fields map 1:1 onto the 40-byte export directory block. Table slots
//! ([`NamedExport::name_rva`], [`NamedExport::name_ordinal_index`], and export
//! address table fields) are [`Field`]s at their real buffer offsets.

use std::collections::HashSet;

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

/// `IMAGE_EXPORT_DIRECTORY` — 40 bytes at the export data directory RVA.
pub struct ExportDirectory {
    /// `Characteristics` (reserved, must be 0).
    pub characteristics: Field<u32>,
    /// `TimeDateStamp`.
    pub time_date_stamp: Field<u32>,
    /// `MajorVersion`.
    pub major_version: Field<u16>,
    /// `MinorVersion`.
    pub minor_version: Field<u16>,
    /// RVA of the DLL name string.
    pub name: Field<u32>,
    /// First valid exported ordinal (`Base`).
    pub base: Field<u32>,
    /// `NumberOfFunctions`.
    pub number_of_functions: Field<u32>,
    /// `NumberOfNames`.
    pub number_of_names: Field<u32>,
    /// RVA of the export address table.
    pub address_of_functions: Field<u32>,
    /// RVA of the export name pointer table.
    pub address_of_names: Field<u32>,
    /// RVA of the export ordinal table.
    pub address_of_name_ordinals: Field<u32>,
}

/// One slot in `AddressOfFunctions`.
pub enum FunctionExport {
    /// RVA points at executable code or data in the image.
    Local {
        /// Exported ordinal (`directory.base` + index).
        ordinal: u16,
        /// Index in `AddressOfFunctions`.
        index: usize,
        /// Function RVA slot.
        function_rva: Field<u32>,
    },
    /// RVA points at a forwarder string inside the export directory.
    Forwarder {
        /// Exported ordinal.
        ordinal: u16,
        /// Index in `AddressOfFunctions`.
        index: usize,
        /// Forwarder RVA slot in `AddressOfFunctions`.
        function_rva: Field<u32>,
        /// Decoded `DLL.Name` forwarder string.
        forwarder: String,
    },
}

/// One named export (`AddressOfNames` / `AddressOfNameOrdinals` row).
pub struct NamedExport {
    /// Decoded export name (NUL-terminated string at [`Self::name_rva`]).
    pub name: String,
    /// Exported ordinal (`directory.base` + name-ordinal index).
    pub ordinal: u16,
    /// Slot in `AddressOfFunctions` for this export.
    pub function_rva: Field<u32>,
    /// Slot in `AddressOfNames` for this export.
    pub name_rva: Field<u32>,
    /// Slot in `AddressOfNameOrdinals` for this export.
    pub name_ordinal_index: Field<u16>,
}

/// Parsed export directory plus function and named export rows.
pub struct Exports {
    /// Export directory header fields.
    pub directory: ExportDirectory,
    /// Full `AddressOfFunctions` table (`number_of_functions` entries).
    pub functions: Vec<FunctionExport>,
    /// Named exports (length = `directory.number_of_names`).
    pub named: Vec<NamedExport>,
}

impl ExportDirectory {
    /// Parses `IMAGE_EXPORT_DIRECTORY` at `offset` in `buffer`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + 40 {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(ExportDirectory {
            characteristics: Field::new(extract_u32(buffer, offset)?, offset, 4),
            time_date_stamp: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            major_version: Field::new(extract_u16(buffer, offset + 8)?, offset + 8, 2),
            minor_version: Field::new(extract_u16(buffer, offset + 10)?, offset + 10, 2),
            name: Field::new(extract_u32(buffer, offset + 12)?, offset + 12, 4),
            base: Field::new(extract_u32(buffer, offset + 16)?, offset + 16, 4),
            number_of_functions: Field::new(extract_u32(buffer, offset + 20)?, offset + 20, 4),
            number_of_names: Field::new(extract_u32(buffer, offset + 24)?, offset + 24, 4),
            address_of_functions: Field::new(extract_u32(buffer, offset + 28)?, offset + 28, 4),
            address_of_names: Field::new(extract_u32(buffer, offset + 32)?, offset + 32, 4),
            address_of_name_ordinals: Field::new(extract_u32(buffer, offset + 36)?, offset + 36, 4),
        })
    }

    /// Reads the DLL name string at [`Self::name`].
    pub fn dll_name(
        &self,
        buffer: &[u8],
        rva_to_offset: impl Fn(u32) -> Result<usize, FileParseError>,
    ) -> Result<String, FileParseError> {
        read_c_string(buffer, rva_to_offset(self.name.value)?)
    }

    /// `true` when `function_rva` falls inside the export directory image range.
    pub fn is_forwarder_rva(
        &self,
        export_dir_rva: u32,
        export_dir_size: u32,
        function_rva: u32,
    ) -> bool {
        function_rva >= export_dir_rva
            && function_rva < export_dir_rva.saturating_add(export_dir_size)
    }
}

impl Exports {
    /// Parses the full export tables from `directory`.
    pub fn parse(
        buffer: &[u8],
        directory: &ExportDirectory,
        export_dir_rva: u32,
        export_dir_size: u32,
        rva_to_offset: impl Fn(u32) -> Result<usize, FileParseError>,
    ) -> Result<Self, FileParseError> {
        let named = Self::parse_named(buffer, directory, &rva_to_offset)?;
        let functions = Self::parse_functions(
            buffer,
            directory,
            export_dir_rva,
            export_dir_size,
            &rva_to_offset,
        )?;
        Ok(Exports {
            directory: ExportDirectory {
                characteristics: directory.characteristics.clone(),
                time_date_stamp: directory.time_date_stamp.clone(),
                major_version: directory.major_version.clone(),
                minor_version: directory.minor_version.clone(),
                name: directory.name.clone(),
                base: directory.base.clone(),
                number_of_functions: directory.number_of_functions.clone(),
                number_of_names: directory.number_of_names.clone(),
                address_of_functions: directory.address_of_functions.clone(),
                address_of_names: directory.address_of_names.clone(),
                address_of_name_ordinals: directory.address_of_name_ordinals.clone(),
            },
            functions,
            named,
        })
    }

    /// Parses named exports from `directory` using `buffer` and `rva_to_offset`.
    pub fn parse_named(
        buffer: &[u8],
        directory: &ExportDirectory,
        rva_to_offset: impl Fn(u32) -> Result<usize, FileParseError>,
    ) -> Result<Vec<NamedExport>, FileParseError> {
        let count = directory.number_of_names.value as usize;
        if count == 0 {
            return Ok(Vec::new());
        }

        let names_table = rva_to_offset(directory.address_of_names.value)?;
        let ordinals_table = rva_to_offset(directory.address_of_name_ordinals.value)?;
        let functions_table = rva_to_offset(directory.address_of_functions.value)?;
        let ordinal_base = directory.base.value;

        let mut named = Vec::with_capacity(count);
        for i in 0..count {
            let name_rva_off = names_table + i * 4;
            let name_rva = Field::new(extract_u32(buffer, name_rva_off)?, name_rva_off, 4);

            let ord_off = ordinals_table + i * 2;
            let name_ordinal_index = Field::new(extract_u16(buffer, ord_off)?, ord_off, 2);

            let func_off = functions_table + name_ordinal_index.value as usize * 4;
            let function_rva = Field::new(extract_u32(buffer, func_off)?, func_off, 4);

            let name = read_c_string(buffer, rva_to_offset(name_rva.value)?)?;
            let ordinal = ordinal_base
                .checked_add(name_ordinal_index.value as u32)
                .and_then(|v| u16::try_from(v).ok())
                .ok_or(FileParseError::ValueTooLarge)?;

            named.push(NamedExport {
                name,
                ordinal,
                function_rva,
                name_rva,
                name_ordinal_index,
            });
        }

        Ok(named)
    }

    /// Parses the full `AddressOfFunctions` table, including ordinal-only and forwarder entries.
    pub fn parse_functions(
        buffer: &[u8],
        directory: &ExportDirectory,
        export_dir_rva: u32,
        export_dir_size: u32,
        rva_to_offset: impl Fn(u32) -> Result<usize, FileParseError>,
    ) -> Result<Vec<FunctionExport>, FileParseError> {
        let count = directory.number_of_functions.value as usize;
        if count == 0 {
            return Ok(Vec::new());
        }

        let functions_table = rva_to_offset(directory.address_of_functions.value)?;
        let ordinal_base = directory.base.value;

        let mut functions = Vec::with_capacity(count);
        for i in 0..count {
            let func_off = functions_table + i * 4;
            let function_rva = Field::new(extract_u32(buffer, func_off)?, func_off, 4);
            let ordinal = ordinal_base
                .checked_add(i as u32)
                .and_then(|v| u16::try_from(v).ok())
                .ok_or(FileParseError::ValueTooLarge)?;

            if directory.is_forwarder_rva(export_dir_rva, export_dir_size, function_rva.value) {
                let forwarder = read_c_string(buffer, rva_to_offset(function_rva.value)?)?;
                functions.push(FunctionExport::Forwarder {
                    ordinal,
                    index: i,
                    function_rva,
                    forwarder,
                });
            } else {
                functions.push(FunctionExport::Local {
                    ordinal,
                    index: i,
                    function_rva,
                });
            }
        }

        Ok(functions)
    }

    /// Returns function table indices that have no corresponding name entry.
    pub fn ordinal_only_exports(&self) -> Vec<&FunctionExport> {
        let named_indices: HashSet<usize> = self
            .named
            .iter()
            .map(|entry| entry.name_ordinal_index.value as usize)
            .collect();

        self.functions
            .iter()
            .filter(|entry| match entry {
                FunctionExport::Local { index, .. } | FunctionExport::Forwarder { index, .. } => {
                    !named_indices.contains(index)
                }
            })
            .collect()
    }
}

fn read_c_string(buffer: &[u8], offset: usize) -> Result<String, FileParseError> {
    let tail = buffer.get(offset..).ok_or(FileParseError::BufferOverflow)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(FileParseError::InvalidFileFormat)?;
    std::str::from_utf8(&tail[..end])
        .map(|s| s.to_owned())
        .map_err(|_| FileParseError::InvalidFileFormat)
}
