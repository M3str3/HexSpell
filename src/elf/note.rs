//! ELF note parsing for `PT_NOTE` and `SHT_NOTE` payloads.

use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// One `Elf_Nhdr` note plus its name and descriptor bytes.
pub struct NoteEntry {
    /// `n_namesz`.
    pub n_namesz: Field<u32>,
    /// `n_descsz`.
    pub n_descsz: Field<u32>,
    /// `n_type`.
    pub n_type: Field<u32>,
    /// Raw note name bytes, including any trailing NUL padding before alignment.
    pub name: Vec<u8>,
    /// Raw descriptor bytes.
    pub desc: Vec<u8>,
}

impl NoteEntry {
    /// Returns the note name without a trailing NUL byte, decoded lossily.
    pub fn name_string(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

/// A note payload parsed from a section or segment.
pub struct NoteTable {
    /// Notes in file order.
    pub entries: Vec<NoteEntry>,
}

impl NoteTable {
    /// Parses notes from `offset..offset + size`.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: usize,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        let mut cursor = offset;
        let mut entries = Vec::new();
        while cursor + 12 <= end {
            let n_namesz = Field::new(order.read_u32(buffer, cursor)?, cursor, 4);
            let n_descsz = Field::new(order.read_u32(buffer, cursor + 4)?, cursor + 4, 4);
            let n_type = Field::new(order.read_u32(buffer, cursor + 8)?, cursor + 8, 4);
            cursor += 12;

            let name_end = cursor
                .checked_add(n_namesz.value as usize)
                .ok_or(FileParseError::BufferOverflow)?;
            let name = buffer
                .get(cursor..name_end)
                .ok_or(FileParseError::BufferOverflow)?
                .to_vec();
            cursor = align4(name_end);

            let desc_end = cursor
                .checked_add(n_descsz.value as usize)
                .ok_or(FileParseError::BufferOverflow)?;
            let desc = buffer
                .get(cursor..desc_end)
                .ok_or(FileParseError::BufferOverflow)?
                .to_vec();
            cursor = align4(desc_end);

            entries.push(NoteEntry {
                n_namesz,
                n_descsz,
                n_type,
                name,
                desc,
            });
        }
        Ok(Self { entries })
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}
