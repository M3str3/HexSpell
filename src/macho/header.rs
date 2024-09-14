use crate::errors;
use crate::field::Field;

#[derive(Debug)]
pub struct MachHeader {
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
    pub fn parse(buffer: &[u8]) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 28 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let magic = Field::new(u32::from_le_bytes(buffer[0..4].try_into().unwrap()), 0, 4);
        let cpu_type = Field::new(u32::from_le_bytes(buffer[4..8].try_into().unwrap()), 4, 4);
        let cpu_subtype = Field::new(u32::from_le_bytes(buffer[8..12].try_into().unwrap()), 8, 4);
        let file_type = Field::new(
            u32::from_le_bytes(buffer[12..16].try_into().unwrap()),
            12,
            4,
        );
        let ncmds = Field::new(
            u32::from_le_bytes(buffer[16..20].try_into().unwrap()),
            16,
            4,
        );
        let sizeofcmds = Field::new(
            u32::from_le_bytes(buffer[20..24].try_into().unwrap()),
            20,
            4,
        );
        let flags = Field::new(
            u32::from_le_bytes(buffer[24..28].try_into().unwrap()),
            24,
            4,
        );

        let reserved: Option<Field<u32>> = if buffer.len() >= 32 {
            Some(Field::new(
                u32::from_le_bytes(buffer[28..32].try_into().unwrap()),
                28,
                4,
            ))
        } else {
            None
        };

        Ok(MachHeader {
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
