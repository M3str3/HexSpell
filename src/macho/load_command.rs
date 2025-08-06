use super::header::Endianness;
use crate::errors;
use crate::field::Field;

#[derive(Debug)]
pub struct LoadCommand {
    pub cmd: Field<u32>,
    pub cmdsize: Field<u32>,
}

impl LoadCommand {
    pub fn parse_load_commands(
        buffer: &[u8],
        offset: usize,
        ncmds: u32,
        endianness: Endianness,
    ) -> Result<Vec<Self>, errors::FileParseError> {
        let mut commands = Vec::new();
        let mut current_offset = offset;

        for _ in 0..ncmds {
            if buffer.len() < current_offset + 8 {
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

            let cmd = Field::new(read_u32(current_offset)?, current_offset, 4);
            let cmdsize = Field::new(read_u32(current_offset + 4)?, current_offset + 4, 4);

            commands.push(LoadCommand { cmd, cmdsize });
            current_offset += cmdsize.value as usize;
        }

        Ok(commands)
    }
}
