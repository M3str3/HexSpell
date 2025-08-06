use crate::errors;
use crate::field::Field;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug)]
pub struct MachHeader {
    pub endianness: Endianness,
    pub magic: Field<u32>,
    pub cpu_type: Field<u32>,
    pub cpu_subtype: Field<u32>,
    pub file_type: Field<u32>,
    pub ncmds: Field<u32>,
    pub sizeofcmds: Field<u32>,
    pub flags: Field<u32>,
    pub reserved: Option<Field<u32>>, // Only Mach-O 64 bits
}

impl MachHeader {
    pub fn parse(buffer: &[u8], endianness: Endianness) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 28 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let read_u32 = |offset: usize| -> Result<u32, errors::FileParseError> {
            let bytes: [u8; 4] = buffer
                .get(offset..offset + 4)
                .ok_or(errors::FileParseError::BufferOverflow)?
                .try_into()
                .map_err(|_| errors::FileParseError::BufferOverflow)?;
            Ok(match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            })
        };

        let magic = Field::new(read_u32(0)?, 0, 4);
        let cpu_type = Field::new(read_u32(4)?, 4, 4);
        let cpu_subtype = Field::new(read_u32(8)?, 8, 4);
        let file_type = Field::new(read_u32(12)?, 12, 4);
        let ncmds = Field::new(read_u32(16)?, 16, 4);
        let sizeofcmds = Field::new(read_u32(20)?, 20, 4);
        let flags = Field::new(read_u32(24)?, 24, 4);

        let reserved: Option<Field<u32>> = if buffer.len() >= 32 {
            Some(Field::new(read_u32(28)?, 28, 4))
        } else {
            None
        };

        Ok(MachHeader {
            endianness,
            magic,
            cpu_type,
            cpu_subtype,
            file_type,
            ncmds,
            sizeofcmds,
            flags,
            reserved,
        })
    }
}
