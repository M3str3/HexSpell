//! Resource directory tree (`IMAGE_RESOURCE_DIRECTORY` / `ENTRY` / `DATA`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

/// `IMAGE_RESOURCE_DIRECTORY` — 16 bytes.
pub struct ResourceDirectory {
    /// Characteristics (reserved).
    pub characteristics: Field<u32>,
    /// Time/date stamp.
    pub time_date_stamp: Field<u32>,
    /// Major version.
    pub major_version: Field<u16>,
    /// Minor version.
    pub minor_version: Field<u16>,
    /// Number of name entries.
    pub number_of_named_entries: Field<u16>,
    /// Number of ID entries.
    pub number_of_id_entries: Field<u16>,
}

/// `IMAGE_RESOURCE_DIRECTORY_ENTRY` — 8 bytes.
pub struct ResourceDirectoryEntry {
    /// Name or ID field (`Name` / `Id`).
    pub name_or_id: Field<u32>,
    /// Offset to data or subdirectory (`OffsetToData`).
    pub offset_to_data: Field<u32>,
}

/// `IMAGE_RESOURCE_DATA_ENTRY` — 16 bytes (leaf).
pub struct ResourceDataEntry {
    /// RVA of the resource data.
    pub offset_to_data: Field<u32>,
    /// Size of the resource data.
    pub size: Field<u32>,
    /// Code page.
    pub code_page: Field<u32>,
    /// Reserved.
    pub reserved: Field<u32>,
}

/// Named or numeric resource directory entry.
pub enum ResourceEntry {
    /// Subdirectory node.
    Directory {
        /// Entry name when named; `None` for ID entries.
        name: Option<String>,
        /// Numeric ID when not named.
        id: Option<u16>,
        /// On-disk directory entry fields.
        entry: ResourceDirectoryEntry,
        /// Parsed child directory.
        directory: ResourceDirectoryNode,
    },
    /// Leaf data entry.
    Data {
        /// Entry name when named; `None` for ID entries.
        name: Option<String>,
        /// Numeric ID when not named.
        id: Option<u16>,
        /// On-disk directory entry fields.
        entry: ResourceDirectoryEntry,
        /// Parsed data entry.
        data: ResourceDataEntry,
    },
}

/// One node in the resource tree.
pub struct ResourceDirectoryNode {
    /// Absolute file offset of this directory header.
    pub offset: usize,
    /// Directory header fields.
    pub header: ResourceDirectory,
    /// Child entries.
    pub entries: Vec<ResourceEntry>,
}

/// Parsed resource directory tree.
pub struct ResourceTree {
    /// Absolute file offset of the root directory.
    pub offset: usize,
    /// Root directory node.
    pub root: ResourceDirectoryNode,
}

impl ResourceDirectory {
    /// Size of `IMAGE_RESOURCE_DIRECTORY` in bytes.
    pub const SIZE: usize = 16;

    /// Parses a resource directory at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(ResourceDirectory {
            characteristics: Field::new(extract_u32(buffer, offset)?, offset, 4),
            time_date_stamp: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            major_version: Field::new(extract_u16(buffer, offset + 8)?, offset + 8, 2),
            minor_version: Field::new(extract_u16(buffer, offset + 10)?, offset + 10, 2),
            number_of_named_entries: Field::new(extract_u16(buffer, offset + 12)?, offset + 12, 2),
            number_of_id_entries: Field::new(extract_u16(buffer, offset + 14)?, offset + 14, 2),
        })
    }
}

impl ResourceDirectoryEntry {
    /// Size of `IMAGE_RESOURCE_DIRECTORY_ENTRY` in bytes.
    pub const SIZE: usize = 8;

    /// Parses a directory entry at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(ResourceDirectoryEntry {
            name_or_id: Field::new(extract_u32(buffer, offset)?, offset, 4),
            offset_to_data: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
        })
    }

    /// `true` when the high bit marks a subdirectory offset.
    pub fn is_directory(&self) -> bool {
        self.offset_to_data.value & 0x8000_0000 != 0
    }

    /// Offset relative to the resource section base.
    pub fn data_offset(&self) -> u32 {
        self.offset_to_data.value & 0x7FFF_FFFF
    }
}

impl ResourceDataEntry {
    /// Size of `IMAGE_RESOURCE_DATA_ENTRY` in bytes.
    pub const SIZE: usize = 16;

    /// Parses a data entry at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        Ok(ResourceDataEntry {
            offset_to_data: Field::new(extract_u32(buffer, offset)?, offset, 4),
            size: Field::new(extract_u32(buffer, offset + 4)?, offset + 4, 4),
            code_page: Field::new(extract_u32(buffer, offset + 8)?, offset + 8, 4),
            reserved: Field::new(extract_u32(buffer, offset + 12)?, offset + 12, 4),
        })
    }
}

impl ResourceTree {
    /// Parses the resource directory tree rooted at `offset`.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        rva_to_offset: impl Fn(u32) -> Result<usize, FileParseError>,
    ) -> Result<Self, FileParseError> {
        let root = parse_node(buffer, offset, offset, &rva_to_offset)?;
        Ok(ResourceTree { offset, root })
    }
}

#[allow(clippy::only_used_in_recursion)]
fn parse_node(
    buffer: &[u8],
    resource_base: usize,
    offset: usize,
    rva_to_offset: &impl Fn(u32) -> Result<usize, FileParseError>,
) -> Result<ResourceDirectoryNode, FileParseError> {
    let header = ResourceDirectory::parse(buffer, offset)?;
    let named_count = header.number_of_named_entries.value as usize;
    let id_count = header.number_of_id_entries.value as usize;
    let entries_offset = offset + ResourceDirectory::SIZE;
    let total = named_count
        .checked_add(id_count)
        .ok_or(FileParseError::ValueTooLarge)?;
    let entries_end = entries_offset
        .checked_add(total * ResourceDirectoryEntry::SIZE)
        .ok_or(FileParseError::BufferOverflow)?;
    if buffer.len() < entries_end {
        return Err(FileParseError::BufferOverflow);
    }

    let mut entries = Vec::with_capacity(total);
    for i in 0..total {
        let entry_off = entries_offset + i * ResourceDirectoryEntry::SIZE;
        let entry = ResourceDirectoryEntry::parse(buffer, entry_off)?;
        let is_named = i < named_count;
        let (name, id) = if is_named {
            let name = read_resource_name(buffer, resource_base, entry.name_or_id.value)?;
            (Some(name), None)
        } else {
            (None, Some(entry.name_or_id.value as u16))
        };

        let child_off = resource_base
            .checked_add(entry.data_offset() as usize)
            .ok_or(FileParseError::BufferOverflow)?;

        if entry.is_directory() {
            let directory = parse_node(buffer, resource_base, child_off, rva_to_offset)?;
            entries.push(ResourceEntry::Directory {
                name,
                id,
                entry,
                directory,
            });
        } else {
            let data = ResourceDataEntry::parse(buffer, child_off)?;
            entries.push(ResourceEntry::Data {
                name,
                id,
                entry,
                data,
            });
        }
    }

    Ok(ResourceDirectoryNode {
        offset,
        header,
        entries,
    })
}

fn read_resource_name(
    buffer: &[u8],
    resource_base: usize,
    name_offset: u32,
) -> Result<String, FileParseError> {
    let off = resource_base
        .checked_add(name_offset as usize)
        .ok_or(FileParseError::BufferOverflow)?;
    if buffer.len() < off + 2 {
        return Err(FileParseError::BufferOverflow);
    }
    let length = u16::from_le_bytes([buffer[off], buffer[off + 1]]) as usize;
    let start = off + 2;
    let end = start
        .checked_add(length * 2)
        .ok_or(FileParseError::BufferOverflow)?;
    let bytes = buffer
        .get(start..end)
        .ok_or(FileParseError::BufferOverflow)?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}
