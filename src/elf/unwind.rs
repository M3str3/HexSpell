//! ELF unwind and exception sections.

use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// Raw section-backed blob with its section index.
pub struct SectionBlob<'a> {
    /// Section index in the ELF section header table.
    pub section_index: usize,
    /// Raw on-disk section bytes.
    pub data: &'a [u8],
}

/// Fixed header of `.eh_frame_hdr`.
pub struct EhFrameHdr {
    /// `version`.
    pub version: Field<u8>,
    /// `eh_frame_ptr_enc`.
    pub eh_frame_ptr_enc: Field<u8>,
    /// `fde_count_enc`.
    pub fde_count_enc: Field<u8>,
    /// `table_enc`.
    pub table_enc: Field<u8>,
    /// Remaining encoded payload bytes.
    pub payload: Vec<u8>,
}

impl EhFrameHdr {
    /// Parses the fixed four-byte `.eh_frame_hdr` prefix.
    pub fn parse(buffer: &[u8], offset: usize, size: usize) -> Result<Self, FileParseError> {
        if size < 4 || buffer.len() < offset + size {
            return Err(FileParseError::BufferOverflow);
        }
        Ok(Self {
            version: Field::new(buffer[offset], offset, 1),
            eh_frame_ptr_enc: Field::new(buffer[offset + 1], offset + 1, 1),
            fde_count_enc: Field::new(buffer[offset + 2], offset + 2, 1),
            table_enc: Field::new(buffer[offset + 3], offset + 3, 1),
            payload: buffer[offset + 4..offset + size].to_vec(),
        })
    }
}

/// One address-sized entry from `.init_array`, `.fini_array`, or `.preinit_array`.
pub struct AddressArrayEntry {
    /// Function pointer value, promoted to `u64`.
    pub value: Field<u64>,
}

/// Parsed init/fini array.
pub struct AddressArray {
    /// Address-sized entries in file order.
    pub entries: Vec<AddressArrayEntry>,
}

impl AddressArray {
    /// Parses an address array using the ELF class pointer width.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: usize,
        width: usize,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        if width != 4 && width != 8 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        let mut cursor = offset;
        let mut entries = Vec::with_capacity(size / width);
        while cursor + width <= end {
            let value = if width == 4 {
                order.read_u32(buffer, cursor)? as u64
            } else {
                order.read_u64(buffer, cursor)?
            };
            entries.push(AddressArrayEntry {
                value: Field::new(value, cursor, width),
            });
            cursor += width;
        }
        Ok(Self { entries })
    }
}
