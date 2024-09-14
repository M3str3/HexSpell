use crate::errors;
use crate::field::Field;

#[derive(Debug, PartialEq, Eq)]
pub enum ElfType {
    None,
    Relocatable,
    Executable,
    SharedObject,
    Core,
    Other(u16),
}

impl From<u16> for ElfType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::SharedObject,
            4 => Self::Core,
            _ => Self::Other(value),
        }
    }
}

#[derive(Debug)]
pub struct ElfHeader {
    pub ident: Vec<u8>,
    pub elf_type: Field<ElfType>,
    pub machine: Field<u16>,
    pub version: Field<u32>,
    pub entry: Field<u64>,
    pub ph_off: Field<u64>,
    pub sh_off: Field<u64>,
    pub flags: Field<u32>,
    pub eh_size: Field<u16>,
    pub ph_ent_size: Field<u16>,
    pub ph_num: Field<u16>,
    pub sh_ent_size: Field<u16>,
    pub sh_num: Field<u16>,
    pub sh_strndx: Field<u16>,
}

impl ElfHeader {
    pub fn parse(buffer: &[u8]) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 64 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let ident: Vec<u8> = buffer[0..16].to_vec();

        let elf_type: Field<ElfType> = Field::new(
            ElfType::from(u16::from_le_bytes([buffer[16], buffer[17]])),
            16,
            2,
        );
        let machine: Field<u16> = Field::new(u16::from_le_bytes([buffer[18], buffer[19]]), 18, 2);
        let version: Field<u32> = Field::new(
            u32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]),
            20,
            4,
        );
        let entry: Field<u64> = Field::new(
            u64::from_le_bytes([
                buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30],
                buffer[31],
            ]),
            24,
            8,
        );
        let ph_off: Field<u64> = Field::new(
            u64::from_le_bytes([
                buffer[32], buffer[33], buffer[34], buffer[35], buffer[36], buffer[37], buffer[38],
                buffer[39],
            ]),
            32,
            8,
        );
        let sh_off: Field<u64> = Field::new(
            u64::from_le_bytes([
                buffer[40], buffer[41], buffer[42], buffer[43], buffer[44], buffer[45], buffer[46],
                buffer[47],
            ]),
            40,
            8,
        );
        let flags: Field<u32> = Field::new(
            u32::from_le_bytes([buffer[48], buffer[49], buffer[50], buffer[51]]),
            48,
            4,
        );
        let eh_size: Field<u16> = Field::new(u16::from_le_bytes([buffer[52], buffer[53]]), 52, 2);
        let ph_ent_size: Field<u16> =
            Field::new(u16::from_le_bytes([buffer[54], buffer[55]]), 54, 2);
        let ph_num: Field<u16> = Field::new(u16::from_le_bytes([buffer[56], buffer[57]]), 56, 2);
        let sh_ent_size: Field<u16> =
            Field::new(u16::from_le_bytes([buffer[58], buffer[59]]), 58, 2);
        let sh_num: Field<u16> = Field::new(u16::from_le_bytes([buffer[60], buffer[61]]), 60, 2);
        let sh_strndx: Field<u16> = Field::new(u16::from_le_bytes([buffer[62], buffer[63]]), 62, 2);

        Ok(ElfHeader {
            ident,
            elf_type,
            machine,
            version,
            entry,
            ph_off,
            sh_off,
            flags,
            eh_size,
            ph_ent_size,
            ph_num,
            sh_ent_size,
            sh_num,
            sh_strndx,
        })
    }
}
