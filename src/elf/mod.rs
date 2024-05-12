use std::fs;
use std::io::Read;

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
pub struct ProgramHeader {
    pub p_type:     Field<u32>,
    pub p_flags:    Field<u32>,
    pub p_offset:   Field<u64>,
    pub p_vaddr:    Field<u64>,
    pub p_paddr:    Field<u64>,
    pub p_filesz:   Field<u64>,
    pub p_memsz:    Field<u64>,
    pub p_align:    Field<u64>,
}

#[derive(Debug)]
pub struct SectionHeader {
    pub sh_name:        Field<u32>,
    pub sh_type:        Field<u32>,
    pub sh_flags:       Field<u64>,
    pub sh_addr:        Field<u64>,
    pub sh_offset:      Field<u64>,
    pub sh_size:        Field<u64>,
    pub sh_link:        Field<u32>,
    pub sh_info:        Field<u32>,
    pub sh_addralign:   Field<u64>,
    pub sh_entsize:     Field<u64>,
}


#[derive(Debug)]
pub struct ElfHeader {
    pub ident: Vec<u8>,             // ELF Magic Number and Class
    pub elf_type: Field<ElfType>,   // ELF Type
    pub machine: Field<u16>,        // Target machine architecture
    pub version: Field<u32>,        // ELF format version
    pub entry: Field<u64>,          // Entry point virtual address
    pub ph_off: Field<u64>,         // Program header table file offset
    pub sh_off: Field<u64>,         // Section header table file offset
    pub flags: Field<u32>,          // Processor-specific flags
    pub eh_size: Field<u16>,        // ELF header size in bytes
    pub ph_ent_size: Field<u16>,    // Size of one entry in the program header table
    pub ph_num: Field<u16>,         // Number of entries in the program header table
    pub sh_ent_size: Field<u16>,    // Size of one entry in the section header table
    pub sh_num: Field<u16>,         // Number of entries in the section header table
    pub sh_strndx: Field<u16>,      // Section header string table index
}

pub struct ELF {
    pub buffer: Vec<u8>,
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
}

impl ELF {
    /// Reads and parses the ELF file from a path.
    pub fn from_file(path: &str) -> Result<Self, errors::FileParseError> {
        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Self::from_buffer(buffer)
    }

    /// Parses the ELF file from a byte buffer.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 64 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let header = parse_elf_header(&buffer)?;
        let program_headers = parse_program_headers(&buffer, header.ph_off.value, header.ph_ent_size.value, header.ph_num.value)?;
        let section_headers = parse_section_headers(&buffer, header.sh_off.value, header.sh_ent_size.value, header.sh_num.value)?;

        Ok(ELF { buffer, header, program_headers, section_headers })
    }
}

fn parse_elf_header(buffer: &[u8]) -> Result<ElfHeader, errors::FileParseError> {
    if buffer.len() < 64 {
        return Err(errors::FileParseError::BufferOverflow);
    }

    let ident = buffer[0..16].to_vec();
    let elf_type = Field::new(ElfType::from(u16::from_le_bytes([buffer[16], buffer[17]])), 16, 2);
    let machine = Field::new(u16::from_le_bytes([buffer[18], buffer[19]]), 18, 2);
    let version = Field::new(u32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]), 20, 4);
    let entry = Field::new(u64::from_le_bytes([buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30], buffer[31]]), 24, 8);
    let ph_off = Field::new(u64::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35], buffer[36], buffer[37], buffer[38], buffer[39]]), 32, 8);
    let sh_off = Field::new(u64::from_le_bytes([buffer[40], buffer[41], buffer[42], buffer[43], buffer[44], buffer[45], buffer[46], buffer[47]]), 40, 8);
    let flags = Field::new(u32::from_le_bytes([buffer[48], buffer[49], buffer[50], buffer[51]]), 48, 4);
    let eh_size = Field::new(u16::from_le_bytes([buffer[52], buffer[53]]), 52, 2);
    let ph_ent_size = Field::new(u16::from_le_bytes([buffer[54], buffer[55]]), 54, 2);
    let ph_num = Field::new(u16::from_le_bytes([buffer[56], buffer[57]]), 56, 2);
    let sh_ent_size = Field::new(u16::from_le_bytes([buffer[58], buffer[59]]), 58, 2);
    let sh_num = Field::new(u16::from_le_bytes([buffer[60], buffer[61]]), 60, 2);
    let sh_strndx = Field::new(u16::from_le_bytes([buffer[62], buffer[63]]), 62, 2);

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


fn parse_program_headers(buffer: &[u8], offset: u64, size: u16, count: u16) -> Result<Vec<ProgramHeader>, errors::FileParseError> {
    let mut headers = Vec::new();
    let start = offset as usize;

    for i in 0..count as usize {
        let base = start + i * size as usize;
        if buffer.len() < base + size as usize {
            return Err(errors::FileParseError::BufferOverflow);
        }

        // Extract each field from the buffer
        let p_type =    Field::new(u32::from_le_bytes(buffer[base..base+4].try_into().unwrap()), base, 4);
        let p_flags =   Field::new(u32::from_le_bytes(buffer[base+4..base+8].try_into().unwrap()), base+4, 4);
        let p_offset =  Field::new(u64::from_le_bytes(buffer[base+8..base+16].try_into().unwrap()), base+8,8);
        let p_vaddr =   Field::new(u64::from_le_bytes(buffer[base+16..base+24].try_into().unwrap()), base+16,8);
        let p_paddr =   Field::new(u64::from_le_bytes(buffer[base+24..base+32].try_into().unwrap()),base+24, 8);
        let p_filesz =  Field::new(u64::from_le_bytes(buffer[base+32..base+40].try_into().unwrap()), base+32, 8);
        let p_memsz =   Field::new(u64::from_le_bytes(buffer[base+40..base+48].try_into().unwrap()), base+40, 8);
        let p_align =   Field::new(u64::from_le_bytes(buffer[base+48..base+56].try_into().unwrap()),base+48, 8);

        headers.push(ProgramHeader {
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align,
        });
    }

    Ok(headers)
}

fn parse_section_headers(buffer: &[u8], offset: u64, size: u16, count: u16) -> Result<Vec<SectionHeader>, errors::FileParseError> {
    let mut headers = Vec::new();
    let start = offset as usize;

    for i in 0..count as usize {
        let base = start + i * size as usize;
        if buffer.len() < base + size as usize {
            return Err(errors::FileParseError::BufferOverflow);
        }

        // Extract each field from the buffer
        let sh_name =       Field::new(u32::from_le_bytes(buffer[base..base+4].try_into().unwrap()), base, 4);
        let sh_type =       Field::new(u32::from_le_bytes(buffer[base+4..base+8].try_into().unwrap()), base+4, 4);
        let sh_flags =      Field::new(u64::from_le_bytes(buffer[base+8..base+16].try_into().unwrap()), base+8, 8);
        let sh_addr =       Field::new(u64::from_le_bytes(buffer[base+16..base+24].try_into().unwrap()), base+16, 8);
        let sh_offset =     Field::new(u64::from_le_bytes(buffer[base+24..base+32].try_into().unwrap()), base+24, 8);
        let sh_size =       Field::new(u64::from_le_bytes(buffer[base+32..base+40].try_into().unwrap()), base+32, 8);
        let sh_link =       Field::new(u32::from_le_bytes(buffer[base+40..base+44].try_into().unwrap()), base+40, 4);
        let sh_info =       Field::new(u32::from_le_bytes(buffer[base+44..base+48].try_into().unwrap()), base+44, 4);
        let sh_addralign =  Field::new(u64::from_le_bytes(buffer[base+48..base+56].try_into().unwrap()), base+48, 8);
        let sh_entsize =    Field::new(u64::from_le_bytes(buffer[base+56..base+64].try_into().unwrap()), base+56, 8);

        headers.push(SectionHeader {
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        });
    }

    Ok(headers)
}


