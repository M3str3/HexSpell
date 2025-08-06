pub mod header;
pub mod load_command;
pub mod segment;

use crate::errors;
use std::fs;
use std::io::{self, Read, Write};

use header::MachHeader;
use load_command::LoadCommand;
use segment::Segment;

pub struct MachO {
    pub buffer: Vec<u8>,
    pub header: MachHeader,
    pub load_commands: Vec<LoadCommand>,
    pub segments: Vec<Segment>,
}

impl MachO {
    /// Write `self.buffer` to disk.
    pub fn write_file(&self, output_path: &str) -> io::Result<()> {
        let mut file = fs::File::create(output_path)?;
        file.write_all(&self.buffer)?;
        Ok(())
    }

    /// Parses a MachO from a specified file path.
    ///
    /// # Arguments
    /// * `path` - A string slice that holds the path to the MachO.
    ///
    /// # Returns
    /// A `Result` that is either a `MachO` on success, or a `FileParseError` on failure.
    ///
    /// # Example
    /// ```
    /// use hexspell::macho::MachO;
    /// let macho_file = MachO::from_file("tests/samples/machO-OSX-x86-ls").unwrap();
    /// ```
    pub fn from_file(path: &str) -> Result<Self, errors::FileParseError> {
        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Self::from_buffer(buffer)
    }

    /// Parses a MachO from a byte vector.
    ///
    /// # Arguments
    /// * `buffer` - A byte vector containing the MachO data.
    ///
    /// # Returns
    /// A `Result` that is either a `MachO` on success, or a `FileParseError` on failure.
    ///
    /// # Example
    /// ```
    /// use hexspell::macho::MachO;
    /// let data = std::fs::read("tests/samples/machO-OSX-x86-ls").expect("Failed to read file");
    /// let macho_file = MachO::from_buffer(data).unwrap();
    /// ```
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 4 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let magic = match buffer.get(0..4) {
            Some(bytes) => u32::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| errors::FileParseError::BufferOverflow)?,
            ),
            None => return Err(errors::FileParseError::BufferOverflow),
        };

        let header_size = match magic {
            0xFEEDFACE => 28, // Mach-O 32-bit
            0xFEEDFACF => 32, // Mach-O 64-bit
            _ => return Err(errors::FileParseError::InvalidFileFormat),
        };

        if buffer.len() < header_size {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let header = MachHeader::parse(&buffer)?;

        let load_commands_offset = header_size;

        if buffer.len() < load_commands_offset + header.sizeofcmds.value as usize {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let load_commands =
            LoadCommand::parse_load_commands(&buffer, load_commands_offset, header.ncmds.value)?;
        let segments = Segment::parse_segments(&buffer, &load_commands)?;

        Ok(MachO {
            buffer,
            header,
            load_commands,
            segments,
        })
    }
}
