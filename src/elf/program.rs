use crate::field::Field;
use crate::errors;

#[derive(Debug)]
pub struct ProgramHeader {
    pub p_type: Field<u32>,
    pub p_flags: Field<u32>,
    pub p_offset: Field<u64>,
    pub p_vaddr: Field<u64>,
    pub p_paddr: Field<u64>,
    pub p_filesz: Field<u64>,
    pub p_memsz: Field<u64>,
    pub p_align: Field<u64>,
}

impl ProgramHeader {
    pub fn parse_program_headers(buffer: &[u8], offset: u64, size: u16, count: u16) -> Result<Vec<ProgramHeader>, errors::FileParseError> {
        let mut headers = Vec::new();
        let start = offset as usize;

        for i in 0..count as usize {
            let base = start + i * size as usize;
            if buffer.len() < base + size as usize {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let p_type = Field::new(u32::from_le_bytes(buffer[base..base+4].try_into().unwrap()), base, 4);
            let p_flags = Field::new(u32::from_le_bytes(buffer[base+4..base+8].try_into().unwrap()), base+4, 4);
            let p_offset = Field::new(u64::from_le_bytes(buffer[base+8..base+16].try_into().unwrap()), base+8, 8);
            let p_vaddr = Field::new(u64::from_le_bytes(buffer[base+16..base+24].try_into().unwrap()), base+16, 8);
            let p_paddr = Field::new(u64::from_le_bytes(buffer[base+24..base+32].try_into().unwrap()), base+24, 8);
            let p_filesz = Field::new(u64::from_le_bytes(buffer[base+32..base+40].try_into().unwrap()), base+32, 8);
            let p_memsz = Field::new(u64::from_le_bytes(buffer[base+40..base+48].try_into().unwrap()), base+40, 8);
            let p_align = Field::new(u64::from_le_bytes(buffer[base+48..base+56].try_into().unwrap()), base+48, 8);

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
}
