use std::io;
use crate::field::Field;

pub struct PeSection {
    pub name: Field<String>,
    pub virtual_size: Field<u32>,
    pub virtual_address: Field<u32>,
    pub size_of_raw_data: Field<u32>,
    pub pointer_to_raw_data: Field<u32>,
    pub pointer_to_relocations: Field<u32>,
    pub pointer_to_linenumbers: Field<u32>,
    pub number_of_relocations: Field<u16>,
    pub number_of_linenumbers: Field<u16>,
    pub characteristics: Field<u32>,
}

impl PeSection {
    /// Parses a section of PE file from a buffer and the offset.
    ///
    /// ## Arguments
    /// * `buffer` - A byte vector containing the PE file data.
    /// * `offset` - A byte vector containing the PE file data.
    ///
    /// ## Returns
    /// A `io::Result` with PeSection
    pub fn parse_section(buffer: &Vec<u8>, offset: usize) -> io::Result<Self> {
        if buffer.len() < offset + 40 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Buffer too small for section"));
        }

        let name = String::from_utf8_lossy(&buffer[offset..offset + 8]).trim_end_matches('\0').to_string();
        let virtual_size = u32::from_le_bytes(buffer[offset + 8..offset + 12].try_into().unwrap());
        let virtual_address = u32::from_le_bytes(buffer[offset + 12..offset + 16].try_into().unwrap());
        let size_of_raw_data = u32::from_le_bytes(buffer[offset + 16..offset + 20].try_into().unwrap());
        let pointer_to_raw_data = u32::from_le_bytes(buffer[offset + 20..offset + 24].try_into().unwrap());
        let pointer_to_relocations = u32::from_le_bytes(buffer[offset + 24..offset + 28].try_into().unwrap());
        let pointer_to_linenumbers = u32::from_le_bytes(buffer[offset + 28..offset + 32].try_into().unwrap());
        let number_of_relocations = u16::from_le_bytes(buffer[offset + 32..offset + 34].try_into().unwrap());
        let number_of_linenumbers = u16::from_le_bytes(buffer[offset + 34..offset + 36].try_into().unwrap());
        let characteristics = u32::from_le_bytes(buffer[offset + 36..offset + 40].try_into().unwrap());

        Ok(PeSection {
            name: Field{
                value: name, offset:offset, size: 8
            },
            virtual_size: Field {
                value: virtual_size, offset: offset + 8, size: 4
            },
            virtual_address: Field {
                value: virtual_address, offset: offset + 12, size: 4
            },
            size_of_raw_data: Field {
                value: size_of_raw_data, offset: offset + 16, size: 4
            },
            pointer_to_raw_data: Field {
                value: pointer_to_raw_data, offset: offset + 20, size: 4
            },
            pointer_to_relocations: Field {
                value: pointer_to_relocations, offset: offset + 24, size: 4
            },
            pointer_to_linenumbers: Field {
                value: pointer_to_linenumbers, offset: offset + 28, size: 4
            },
            number_of_relocations: Field {
                value: number_of_relocations, offset: offset + 32, size: 4
            },
            number_of_linenumbers: Field {
                value: number_of_linenumbers, offset: offset + 34, size: 2
            },
            characteristics: Field {
                value: characteristics, offset: offset + 36, size: 4
            },
        })
    }
}