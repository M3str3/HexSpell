//! ELF section groups and COMDAT metadata.

use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// `GRP_COMDAT` flag in an `SHT_GROUP` section.
pub const GRP_COMDAT: u32 = 1;

/// Parsed `SHT_GROUP` section.
pub struct SectionGroup {
    /// Section index of the `SHT_GROUP` section.
    pub section_index: usize,
    /// Group flags (`GRP_*`).
    pub flags: Field<u32>,
    /// Section indices that belong to the group.
    pub members: Vec<Field<u32>>,
}

impl SectionGroup {
    /// Returns true when the group uses COMDAT semantics.
    pub fn is_comdat(&self) -> bool {
        self.flags.value & GRP_COMDAT != 0
    }

    /// Parses an `SHT_GROUP` payload.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: usize,
        section_index: usize,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        if size < 4 {
            return Err(FileParseError::BufferOverflow);
        }
        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        let flags = Field::new(order.read_u32(buffer, offset)?, offset, 4);
        let mut cursor = offset + 4;
        let mut members = Vec::new();
        while cursor + 4 <= end {
            members.push(Field::new(order.read_u32(buffer, cursor)?, cursor, 4));
            cursor += 4;
        }
        Ok(Self {
            section_index,
            flags,
            members,
        })
    }
}
