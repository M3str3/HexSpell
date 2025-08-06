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

#[derive(Debug, Clone, Copy)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug)]
pub struct ElfHeader {
    pub ident: Vec<u8>,
    pub endianness: Endianness,
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

        // Check magic bytes
        if buffer[0..4] != [0x7F, b'E', b'L', b'F'] {
            return Err(errors::FileParseError::InvalidFileFormat);
        }

        let ident: Vec<u8> = buffer[0..16].to_vec();
        let endianness = match buffer[5] {
            1 => Endianness::Little,
            2 => Endianness::Big,
            _ => return Err(errors::FileParseError::InvalidFileFormat),
        };

        let read_u16 = |offset: usize| -> u16 {
            let bytes = [buffer[offset], buffer[offset + 1]];
            match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            }
        };
        let read_u32 = |offset: usize| -> u32 {
            let bytes = [
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };
        let read_u64 = |offset: usize| -> u64 {
            let bytes = [
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
                buffer[offset + 4],
                buffer[offset + 5],
                buffer[offset + 6],
                buffer[offset + 7],
            ];
            match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            }
        };

        let elf_type: Field<ElfType> = Field::new(ElfType::from(read_u16(16)), 16, 2);
        let machine: Field<u16> = Field::new(read_u16(18), 18, 2);
        let version: Field<u32> = Field::new(read_u32(20), 20, 4);
        let entry: Field<u64> = Field::new(read_u64(24), 24, 8);
        let ph_off: Field<u64> = Field::new(read_u64(32), 32, 8);
        let sh_off: Field<u64> = Field::new(read_u64(40), 40, 8);
        let flags: Field<u32> = Field::new(read_u32(48), 48, 4);
        let eh_size: Field<u16> = Field::new(read_u16(52), 52, 2);
        let ph_ent_size: Field<u16> = Field::new(read_u16(54), 54, 2);
        let ph_num: Field<u16> = Field::new(read_u16(56), 56, 2);
        let sh_ent_size: Field<u16> = Field::new(read_u16(58), 58, 2);
        let sh_num: Field<u16> = Field::new(read_u16(60), 60, 2);
        let sh_strndx: Field<u16> = Field::new(read_u16(62), 62, 2);

        Ok(ElfHeader {
            ident,
            endianness,
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
