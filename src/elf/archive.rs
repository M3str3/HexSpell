//! Minimal Unix `ar` archive reader for ELF object archives.

use crate::errors::FileParseError;
use crate::field::Field;

const GLOBAL_MAGIC: &[u8; 8] = b"!<arch>\n";

/// One archive member header.
pub struct ArchiveMember {
    /// File offset of the 60-byte member header.
    pub header_offset: usize,
    /// Member name as stored in the fixed header.
    pub name: Field<String>,
    /// Decimal timestamp text.
    pub timestamp: Field<String>,
    /// Decimal owner id text.
    pub owner_id: Field<String>,
    /// Decimal group id text.
    pub group_id: Field<String>,
    /// Octal mode text.
    pub mode: Field<String>,
    /// Decimal payload size.
    pub size: Field<u64>,
    /// File offset of member payload.
    pub data_offset: usize,
}

impl ArchiveMember {
    /// Returns the raw member payload.
    pub fn data<'a>(&self, buffer: &'a [u8]) -> Result<&'a [u8], FileParseError> {
        let end = self
            .data_offset
            .checked_add(self.size.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        buffer
            .get(self.data_offset..end)
            .ok_or(FileParseError::BufferOverflow)
    }
}

/// Parsed `ar` archive.
pub struct Archive {
    /// Archive members in file order.
    pub members: Vec<ArchiveMember>,
}

impl Archive {
    /// Returns true when `buffer` starts with the global `ar` magic.
    pub fn is_archive(buffer: &[u8]) -> bool {
        buffer.starts_with(GLOBAL_MAGIC)
    }

    /// Parses a basic Unix `ar` archive. Extended filename tables are left raw.
    pub fn parse(buffer: &[u8]) -> Result<Self, FileParseError> {
        if !Self::is_archive(buffer) {
            return Err(FileParseError::InvalidFileFormat);
        }
        let mut cursor = GLOBAL_MAGIC.len();
        let mut members = Vec::new();
        while cursor + 60 <= buffer.len() {
            let header_offset = cursor;
            let name = field_string(buffer, cursor, 16)?;
            let timestamp = field_string(buffer, cursor + 16, 12)?;
            let owner_id = field_string(buffer, cursor + 28, 6)?;
            let group_id = field_string(buffer, cursor + 34, 6)?;
            let mode = field_string(buffer, cursor + 40, 8)?;
            let size_text = field_string(buffer, cursor + 48, 10)?;
            if buffer.get(cursor + 58..cursor + 60) != Some(&b"`\n"[..]) {
                return Err(FileParseError::InvalidFileFormat);
            }
            let size = size_text
                .value
                .trim()
                .parse::<u64>()
                .map_err(|_| FileParseError::InvalidFileFormat)?;
            let data_offset = cursor + 60;
            members.push(ArchiveMember {
                header_offset,
                name,
                timestamp,
                owner_id,
                group_id,
                mode,
                size: Field::new(size, cursor + 48, 10),
                data_offset,
            });
            cursor = data_offset
                .checked_add(size as usize)
                .ok_or(FileParseError::BufferOverflow)?;
            if cursor % 2 != 0 {
                cursor += 1;
            }
        }
        Ok(Self { members })
    }
}

fn field_string(
    buffer: &[u8],
    offset: usize,
    size: usize,
) -> Result<Field<String>, FileParseError> {
    let bytes = buffer
        .get(offset..offset + size)
        .ok_or(FileParseError::BufferOverflow)?;
    Ok(Field::new(
        String::from_utf8_lossy(bytes).trim_end().to_string(),
        offset,
        size,
    ))
}
