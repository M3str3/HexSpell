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
    ) -> Result<Vec<SectionHeader>, errors::FileParseError> {
        let mut headers = Vec::new();
        let start = offset as usize;

        for i in 0..count as usize {
            let base = start + i * size as usize;
            if buffer.len() < base + size as usize {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let sh_name = Field::new(
                u32::from_le_bytes(
                    buffer[base..base + 4]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base,
                4,
            );
            let sh_type = Field::new(
                u32::from_le_bytes(
                    buffer[base + 4..base + 8]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 4,
                4,
            );
            let sh_flags = Field::new(
                u64::from_le_bytes(
                    buffer[base + 8..base + 16]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 8,
                8,
            );
            let sh_addr = Field::new(
                u64::from_le_bytes(
                    buffer[base + 16..base + 24]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 16,
                8,
            );
            let sh_offset = Field::new(
                u64::from_le_bytes(
                    buffer[base + 24..base + 32]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 24,
                8,
            );
            let sh_size = Field::new(
                u64::from_le_bytes(
                    buffer[base + 32..base + 40]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 32,
                8,
            );
            let sh_link = Field::new(
                u32::from_le_bytes(
                    buffer[base + 40..base + 44]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 40,
                4,
            );
            let sh_info = Field::new(
                u32::from_le_bytes(
                    buffer[base + 44..base + 48]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 44,
                4,
            );
            let sh_addralign = Field::new(
                u64::from_le_bytes(
                    buffer[base + 48..base + 56]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 48,
                8,
            );
            let sh_entsize = Field::new(
                u64::from_le_bytes(
                    buffer[base + 56..base + 64]
                        .try_into()
                        .map_err(|_| errors::FileParseError::BufferOverflow)?,
                ),
                base + 56,
                8,
            );

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
