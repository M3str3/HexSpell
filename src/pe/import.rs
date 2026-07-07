//! Import directory structures (`IMAGE_IMPORT_DESCRIPTOR`, `IMAGE_IMPORT_BY_NAME`).
//!
//! Parsing is read-only: descriptors and thunk slots are exposed as [`Field`] values
//! with real file offsets so callers can patch the underlying buffer later.

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::header::PEType;
use crate::pe::section::PeSection;
use crate::utils::{extract_u16, extract_u32, extract_u64};

/// `IMAGE_IMPORT_DESCRIPTOR` — one imported DLL (20 bytes).
pub struct ImageImportDescriptor {
    /// Original First Thunk (ILT) RVA; `0` means use [`Self::first_thunk`].
    pub original_first_thunk: Field<u32>,
    /// Time/date stamp (`0` until bound).
    pub time_date_stamp: Field<u32>,
    /// Forwarder chain index.
    pub forwarder_chain: Field<u32>,
    /// RVA of the NUL-terminated DLL name.
    pub name: Field<u32>,
    /// First Thunk (IAT) RVA.
    pub first_thunk: Field<u32>,
}

/// `IMAGE_IMPORT_BY_NAME` — hint + import name.
pub struct ImageImportByName {
    /// Export name table hint.
    pub hint: Field<u16>,
    /// Absolute file offset of the name bytes.
    pub name_offset: usize,
    /// Decoded import name (ASCII/UTF-8 lossy).
    pub name: String,
}

/// One slot in the ILT or IAT.
pub enum ThunkSlot {
    /// PE32 thunk (`u32` on disk).
    U32(Field<u32>),
    /// PE32+ thunk (`u64` on disk).
    U64(Field<u64>),
}

impl ThunkSlot {
    /// Raw thunk value from the file (ordinal bit may be set).
    pub fn raw_value(&self) -> u64 {
        match self {
            ThunkSlot::U32(f) => f.value as u64,
            ThunkSlot::U64(f) => f.value,
        }
    }

    /// Absolute file offset of this thunk slot.
    pub fn offset(&self) -> usize {
        match self {
            ThunkSlot::U32(f) => f.offset,
            ThunkSlot::U64(f) => f.offset,
        }
    }
}

/// Resolved import entry (ordinal or by name).
pub enum ImportEntry {
    /// Import by ordinal (`IMAGE_ORDINAL_FLAG` set).
    Ordinal { ordinal: u16, thunk: ThunkSlot },
    /// Import by name (`IMAGE_IMPORT_BY_NAME`).
    ByName {
        by_name: ImageImportByName,
        thunk: ThunkSlot,
    },
}

/// Imports from a single DLL.
pub struct DllImport {
    /// On-disk descriptor fields.
    pub descriptor: ImageImportDescriptor,
    /// Absolute file offset of the DLL name string.
    pub dll_name_offset: usize,
    /// Decoded DLL name (e.g. `KERNEL32.dll`).
    pub dll_name: String,
    /// ILT/IAT entries in file order (terminator excluded).
    pub entries: Vec<ImportEntry>,
}

/// Read-only view of the PE import directory.
pub struct ImportDirectory {
    /// Absolute file offset where the descriptor array starts.
    pub offset: usize,
    /// Parsed descriptors (null terminator excluded).
    pub descriptors: Vec<ImageImportDescriptor>,
    /// Resolved DLL imports.
    pub dlls: Vec<DllImport>,
}

impl ImageImportDescriptor {
    /// Size of `IMAGE_IMPORT_DESCRIPTOR` in bytes.
    pub const SIZE: usize = 20;

    /// Parses one descriptor at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(ImageImportDescriptor {
            original_first_thunk: Field::new(extract_u32(buffer, offset)?, offset, 4),
            time_date_stamp: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            forwarder_chain: Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4),
            name: Field::new(extract_u32(buffer, offset + 12)?, offset + 12, 4),
            first_thunk: Field::new(extract_u32(buffer, offset + 16)?, offset + 16, 4),
        })
    }

    /// `true` when all fields are zero (end of descriptor array).
    pub fn is_null(&self) -> bool {
        self.original_first_thunk.value == 0
            && self.time_date_stamp.value == 0
            && self.forwarder_chain.value == 0
            && self.name.value == 0
            && self.first_thunk.value == 0
    }
}

impl ImageImportByName {
    /// Parses `IMAGE_IMPORT_BY_NAME` at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        let hint = extract_u16(buffer, offset)?;
        let name_offset = offset + 2;
        let name = read_c_string(buffer, name_offset)?;
        Ok(ImageImportByName {
            hint: Field::new(hint, offset, 2),
            name_offset,
            name,
        })
    }
}

impl ImportDirectory {
    /// Parses the import directory from `buffer` using section headers for RVA translation.
    pub fn parse(
        buffer: &[u8],
        sections: &[PeSection],
        import_rva: u32,
        pe_type: PEType,
    ) -> Result<Self, FileParseError> {
        if import_rva == 0 {
            return Ok(ImportDirectory {
                offset: 0,
                descriptors: Vec::new(),
                dlls: Vec::new(),
            });
        }

        let offset = rva_to_offset(buffer, sections, import_rva)?;

        let mut descriptors = Vec::new();
        let mut cursor = offset;
        loop {
            let desc = ImageImportDescriptor::parse(buffer, cursor)?;
            if desc.is_null() {
                break;
            }
            descriptors.push(desc);
            cursor += ImageImportDescriptor::SIZE;
        }

        let dlls = descriptors
            .iter()
            .map(|desc| parse_dll_import(buffer, sections, desc, pe_type))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ImportDirectory {
            offset,
            descriptors,
            dlls,
        })
    }
}

fn parse_dll_import(
    buffer: &[u8],
    sections: &[PeSection],
    desc: &ImageImportDescriptor,
    pe_type: PEType,
) -> Result<DllImport, FileParseError> {
    let name_rva = desc.name.value;
    let dll_name_offset = rva_to_offset(buffer, sections, name_rva)?;
    let dll_name = read_c_string(buffer, dll_name_offset)?;

    let thunk_rva = if desc.original_first_thunk.value != 0 {
        desc.original_first_thunk.value
    } else {
        desc.first_thunk.value
    };

    let entries = parse_thunk_table(buffer, sections, thunk_rva, pe_type)?;

    Ok(DllImport {
        descriptor: ImageImportDescriptor {
            original_first_thunk: desc.original_first_thunk.clone(),
            time_date_stamp: desc.time_date_stamp.clone(),
            forwarder_chain: desc.forwarder_chain.clone(),
            name: desc.name.clone(),
            first_thunk: desc.first_thunk.clone(),
        },
        dll_name_offset,
        dll_name,
        entries,
    })
}

pub(crate) fn parse_thunk_table(
    buffer: &[u8],
    sections: &[PeSection],
    thunk_rva: u32,
    pe_type: PEType,
) -> Result<Vec<ImportEntry>, FileParseError> {
    if thunk_rva == 0 {
        return Ok(Vec::new());
    }

    let mut offset = rva_to_offset(buffer, sections, thunk_rva)?;
    let mut entries = Vec::new();

    loop {
        match pe_type {
            PEType::PE32 => {
                let value = extract_u32(buffer, offset)?;
                if value == 0 {
                    break;
                }
                let thunk = ThunkSlot::U32(Field::new(value, offset, 4));
                entries.push(resolve_thunk_entry(buffer, sections, &thunk, PEType::PE32)?);
                offset += 4;
            }
            PEType::PE32Plus => {
                let value = extract_u64(buffer, offset)?;
                if value == 0 {
                    break;
                }
                let thunk = ThunkSlot::U64(Field::new(value, offset, 8));
                entries.push(resolve_thunk_entry(
                    buffer,
                    sections,
                    &thunk,
                    PEType::PE32Plus,
                )?);
                offset += 8;
            }
        }
    }

    Ok(entries)
}

fn resolve_thunk_entry(
    buffer: &[u8],
    sections: &[PeSection],
    thunk: &ThunkSlot,
    pe_type: PEType,
) -> Result<ImportEntry, FileParseError> {
    let raw = thunk.raw_value();
    let ordinal_flag = match pe_type {
        PEType::PE32 => 1u64 << 31,
        PEType::PE32Plus => 1u64 << 63,
    };

    if raw & ordinal_flag != 0 {
        return Ok(ImportEntry::Ordinal {
            ordinal: (raw & 0xFFFF) as u16,
            thunk: thunk.clone_slot(),
        });
    }

    let by_name_offset = rva_to_offset(buffer, sections, raw as u32)?;
    let by_name = ImageImportByName::parse(buffer, by_name_offset)?;

    Ok(ImportEntry::ByName {
        by_name,
        thunk: thunk.clone_slot(),
    })
}

impl ThunkSlot {
    fn clone_slot(&self) -> Self {
        match self {
            ThunkSlot::U32(f) => ThunkSlot::U32(f.clone()),
            ThunkSlot::U64(f) => ThunkSlot::U64(f.clone()),
        }
    }
}

/// Maps a relative virtual address to an absolute file offset using section headers.
pub fn rva_to_offset(
    buffer: &[u8],
    sections: &[PeSection],
    rva: u32,
) -> Result<usize, FileParseError> {
    if rva == 0 {
        return Err(FileParseError::InvalidFileFormat);
    }

    if let Some(first) = sections.first() {
        if rva < first.virtual_address.value {
            let off = usize::try_from(rva).map_err(|_| FileParseError::ValueTooLarge)?;
            if off < buffer.len() {
                return Ok(off);
            }
            return Err(FileParseError::BufferOverflow);
        }
    }

    for section in sections {
        let va = section.virtual_address.value;
        let raw_size = section.size_of_raw_data.value;
        if raw_size == 0 {
            continue;
        }
        if rva >= va && rva < va.saturating_add(raw_size) {
            let offset = section.pointer_to_raw_data.value as usize + (rva - va) as usize;
            if offset < buffer.len() {
                return Ok(offset);
            }
            return Err(FileParseError::BufferOverflow);
        }
    }

    Err(FileParseError::InvalidFileFormat)
}

fn read_c_string(buffer: &[u8], offset: usize) -> Result<String, FileParseError> {
    let tail = buffer.get(offset..).ok_or(FileParseError::BufferOverflow)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(FileParseError::InvalidFileFormat)?;
    let bytes = &tail[..end];
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// Parses imports from a PE image buffer (convenience wrapper).
pub fn parse_import_directory(
    buffer: &[u8],
    sections: &[PeSection],
    import_rva: u32,
    pe_type: PEType,
) -> Result<ImportDirectory, FileParseError> {
    ImportDirectory::parse(buffer, sections, import_rva, pe_type)
}

/// Returns import names for `dll_name` (case-insensitive), if present.
pub fn import_names_for_dll<'a>(imports: &'a ImportDirectory, dll_name: &str) -> Vec<&'a str> {
    imports
        .dlls
        .iter()
        .find(|dll| dll.dll_name.eq_ignore_ascii_case(dll_name))
        .map(|dll| {
            dll.entries
                .iter()
                .filter_map(|entry| match entry {
                    ImportEntry::ByName { by_name, .. } => Some(by_name.name.as_str()),
                    ImportEntry::Ordinal { .. } => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::header::IMPORT;
    use crate::pe::PE;

    #[test]
    fn sample1_import_directory() {
        let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
        let import_rva = pe.optional_header.data_directories[IMPORT]
            .virtual_address
            .value;
        let imports = ImportDirectory::parse(
            &pe.buffer,
            &pe.sections,
            import_rva,
            pe.optional_header.pe_type().unwrap(),
        )
        .unwrap();

        assert_eq!(import_rva, 0x9000);
        assert_eq!(imports.offset, 0x4c00);
        assert_eq!(imports.descriptors.len(), 5);
        assert_eq!(imports.dlls.len(), 5);

        let first = &imports.descriptors[0];
        assert_eq!(first.original_first_thunk.value, 0x9078);
        assert_eq!(first.original_first_thunk.offset, 0x4c00);
        assert_eq!(first.time_date_stamp.value, 0);
        assert_eq!(first.forwarder_chain.value, 0);
        assert_eq!(first.name.value, 0x96dc);
        assert_eq!(first.first_thunk.value, 0x9184);
        assert_eq!(first.first_thunk.offset, 0x4c10);

        let kernel32 = &imports.dlls[0];
        assert_eq!(kernel32.dll_name, "KERNEL32.dll");
        assert!(kernel32.entries.iter().any(|e| {
            matches!(
                e,
                ImportEntry::ByName { by_name, .. } if by_name.name == "ExitProcess"
            )
        }));

        let names: Vec<_> = imports.dlls.iter().map(|d| d.dll_name.as_str()).collect();
        assert_eq!(
            names,
            [
                "KERNEL32.dll",
                "msvcrt.dll",
                "msvcrt.dll",
                "libgcc_s_dw2-1.dll",
                "libstdc++-6.dll",
            ]
        );

        let cpp = imports.dlls.last().unwrap();
        assert!(cpp.entries.iter().any(|e| {
            matches!(
                e,
                ImportEntry::ByName { by_name, .. }
                    if by_name.name == "_ZNSolsEPFRSoS_E"
            )
        }));

        let first_thunk = match &kernel32.entries[0] {
            ImportEntry::ByName { thunk, .. } => thunk,
            _ => panic!("expected by-name import"),
        };
        assert_eq!(first_thunk.offset(), 0x4c78);
    }
}
