use crate::errors;
use crate::field::Field;
use crate::macho::load_command::LoadCommand;

#[derive(Debug)]
pub struct Segment {
    pub name: String,
    pub vmaddr: Field<u64>,
    pub vmsize: Field<u64>,
    pub fileoff: Field<u64>,
    pub filesize: Field<u64>,
    pub maxprot: Field<u32>,
    pub initprot: Field<u32>,
    pub nsects: Field<u32>,
    pub flags: Field<u32>,
}

impl Segment {
    pub fn parse_segments(
        buffer: &[u8],
        load_commands: &[LoadCommand],
    ) -> Result<Vec<Self>, errors::FileParseError> {
        let mut segments = Vec::new();

        for cmd in load_commands {
            if cmd.cmd.value == 0x1 /* LC_SEGMENT */ || cmd.cmd.value == 0x19
            /* LC_SEGMENT_64 */
            {
                let offset = cmd.cmd.offset;
                let name = String::from_utf8_lossy(&buffer[offset + 8..offset + 24])
                    .trim_end_matches('\0')
                    .to_string();
                let vmaddr = Field::new(
                    u64::from_le_bytes(buffer[offset + 24..offset + 32].try_into().unwrap()),
                    offset + 24,
                    8,
                );
                let vmsize = Field::new(
                    u64::from_le_bytes(buffer[offset + 32..offset + 40].try_into().unwrap()),
                    offset + 32,
                    8,
                );
                let fileoff = Field::new(
                    u64::from_le_bytes(buffer[offset + 40..offset + 48].try_into().unwrap()),
                    offset + 40,
                    8,
                );
                let filesize = Field::new(
                    u64::from_le_bytes(buffer[offset + 48..offset + 56].try_into().unwrap()),
                    offset + 48,
                    8,
                );
                let maxprot = Field::new(
                    u32::from_le_bytes(buffer[offset + 56..offset + 60].try_into().unwrap()),
                    offset + 56,
                    4,
                );
                let initprot = Field::new(
                    u32::from_le_bytes(buffer[offset + 60..offset + 64].try_into().unwrap()),
                    offset + 60,
                    4,
                );
                let nsects = Field::new(
                    u32::from_le_bytes(buffer[offset + 64..offset + 68].try_into().unwrap()),
                    offset + 64,
                    4,
                );
                let flags = Field::new(
                    u32::from_le_bytes(buffer[offset + 68..offset + 72].try_into().unwrap()),
                    offset + 68,
                    4,
                );

                segments.push(Segment {
                    name,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    nsects,
                    flags,
                });
            }
        }

        Ok(segments)
    }
}
