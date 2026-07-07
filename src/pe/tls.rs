//! Thread local storage directory (`IMAGE_TLS_DIRECTORY32` / `IMAGE_TLS_DIRECTORY64`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::pe::header::{ImageBase, PEType};
use crate::utils::{extract_u32, extract_u64};

/// TLS directory fields (PE32 or PE32+ layout).
pub struct TlsDirectory {
    /// Start VA of the TLS template (`StartAddressOfRawData`).
    pub start_address_of_raw_data: Field<ImageBase>,
    /// End VA of the TLS template (`EndAddressOfRawData`).
    pub end_address_of_raw_data: Field<ImageBase>,
    /// VA of the TLS index variable (`AddressOfIndex`).
    pub address_of_index: Field<ImageBase>,
    /// VA of the TLS callback pointer array (`AddressOfCallBacks`).
    pub address_of_callbacks: Field<ImageBase>,
    /// Size of zero-filled TLS data (`SizeOfZeroFill`).
    pub size_of_zero_fill: Field<u32>,
    /// `Characteristics` flags.
    pub characteristics: Field<u32>,
}

impl TlsDirectory {
    /// Parses `IMAGE_TLS_DIRECTORY` at `offset` for the given PE type.
    pub fn parse(buffer: &[u8], offset: usize, pe_type: PEType) -> Result<Self, FileParseError> {
        match pe_type {
            PEType::PE32 => {
                if buffer.len() < offset + 24 {
                    return Err(FileParseError::BufferOverflow);
                }
                Ok(TlsDirectory {
                    start_address_of_raw_data: Field::new(
                        ImageBase::Base32(extract_u32(buffer, offset)?),
                        offset,
                        4,
                    ),
                    end_address_of_raw_data: Field::new(
                        ImageBase::Base32(extract_u32(buffer, offset + 4)?),
                        offset + 4,
                        4,
                    ),
                    address_of_index: Field::new(
                        ImageBase::Base32(extract_u32(buffer, offset + 8)?),
                        offset + 8,
                        4,
                    ),
                    address_of_callbacks: Field::new(
                        ImageBase::Base32(extract_u32(buffer, offset + 12)?),
                        offset + 12,
                        4,
                    ),
                    size_of_zero_fill: Field::new(
                        extract_u32(buffer, offset + 16)?,
                        offset + 16,
                        4,
                    ),
                    characteristics: Field::new(extract_u32(buffer, offset + 20)?, offset + 20, 4),
                })
            }
            PEType::PE32Plus => {
                if buffer.len() < offset + 40 {
                    return Err(FileParseError::BufferOverflow);
                }
                Ok(TlsDirectory {
                    start_address_of_raw_data: Field::new(
                        ImageBase::Base64(extract_u64(buffer, offset)?),
                        offset,
                        8,
                    ),
                    end_address_of_raw_data: Field::new(
                        ImageBase::Base64(extract_u64(buffer, offset + 8)?),
                        offset + 8,
                        8,
                    ),
                    address_of_index: Field::new(
                        ImageBase::Base64(extract_u64(buffer, offset + 16)?),
                        offset + 16,
                        8,
                    ),
                    address_of_callbacks: Field::new(
                        ImageBase::Base64(extract_u64(buffer, offset + 24)?),
                        offset + 24,
                        8,
                    ),
                    size_of_zero_fill: Field::new(
                        extract_u32(buffer, offset + 32)?,
                        offset + 32,
                        4,
                    ),
                    characteristics: Field::new(extract_u32(buffer, offset + 36)?, offset + 36, 4),
                })
            }
        }
    }
}
