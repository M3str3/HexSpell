use super::header::Endianness;
use crate::errors;
use crate::field::Field;

#[derive(Debug)]
pub struct SectionHeader {
    pub sh_name: Field<u32>,
    pub sh_type: Field<u32>,
    pub sh_flags: Field<u64>,
    pub sh_addr: Field<u64>,
    pub sh_offset: Field<u64>,
    pub sh_size: Field<u64>,
    pub sh_link: Field<u32>,
    pub sh_info: Field<u32>,
    pub sh_addralign: Field<u64>,
    pub sh_entsize: Field<u64>,
}

impl SectionHeader {
    pub fn parse_section_headers(
        buffer: &[u8],
        offset: u64,
        size: u16,
        count: u16,
        endianness: Endianness,
    ) -> Result<Vec<SectionHeader>, errors::FileParseError> {
        let mut headers = Vec::new();
        let start = offset as usize;

        for i in 0..count as usize {
            let base = start + i * size as usize;
            if buffer.len() < base + size as usize {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let read_u32 = |slice: &[u8]| -> Result<u32, errors::FileParseError> {
                let arr: [u8; 4] = slice
                    .try_into()
                    .map_err(|_| errors::FileParseError::BufferOverflow)?;
                Ok(match endianness {
                    Endianness::Little => u32::from_le_bytes(arr),
                    Endianness::Big => u32::from_be_bytes(arr),
                })
            };
            let read_u64 = |slice: &[u8]| -> Result<u64, errors::FileParseError> {
                let arr: [u8; 8] = slice
                    .try_into()
                    .map_err(|_| errors::FileParseError::BufferOverflow)?;
                Ok(match endianness {
                    Endianness::Little => u64::from_le_bytes(arr),
                    Endianness::Big => u64::from_be_bytes(arr),
                })
            };

            let sh_name = Field::new(read_u32(&buffer[base..base + 4])?, base, 4);
            let sh_type = Field::new(read_u32(&buffer[base + 4..base + 8])?, base + 4, 4);
            let sh_flags = Field::new(read_u64(&buffer[base + 8..base + 16])?, base + 8, 8);
            let sh_addr = Field::new(read_u64(&buffer[base + 16..base + 24])?, base + 16, 8);
            let sh_offset = Field::new(read_u64(&buffer[base + 24..base + 32])?, base + 24, 8);
            let sh_size = Field::new(read_u64(&buffer[base + 32..base + 40])?, base + 32, 8);
            let sh_link = Field::new(read_u32(&buffer[base + 40..base + 44])?, base + 40, 4);
            let sh_info = Field::new(read_u32(&buffer[base + 44..base + 48])?, base + 44, 4);
            let sh_addralign = Field::new(read_u64(&buffer[base + 48..base + 56])?, base + 48, 8);
            let sh_entsize = Field::new(read_u64(&buffer[base + 56..base + 64])?, base + 56, 8);

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
}
