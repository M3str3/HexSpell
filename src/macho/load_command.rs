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
    ) -> Result<Vec<Self>, errors::FileParseError> {
        let mut commands = Vec::new();
        let mut current_offset = offset;

        for _ in 0..ncmds {
            if buffer.len() < current_offset + 8 {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let cmd = Field::new(
                u32::from_le_bytes(
                    buffer[current_offset..current_offset + 4]
                        .try_into()
                        .unwrap(),
                ),
                current_offset,
                4,
            );
            let cmdsize = Field::new(
                u32::from_le_bytes(
                    buffer[current_offset + 4..current_offset + 8]
                        .try_into()
                        .unwrap(),
                ),
                current_offset + 4,
                4,
            );

            commands.push(LoadCommand { cmd, cmdsize });
            current_offset += cmdsize.value as usize;
        }

        Ok(commands)
    }
}
