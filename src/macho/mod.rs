pub mod header;
pub mod load_command;
pub mod segment;

use crate::errors;
use std::fs;
use std::io::{self, Read, Write};

use header::{Endianness, MachHeader};
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

        let magic_bytes: [u8; 4] = buffer
            .get(0..4)
            .ok_or(errors::FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| errors::FileParseError::BufferOverflow)?;

        let magic_be = u32::from_be_bytes(magic_bytes);
        let magic_le = u32::from_le_bytes(magic_bytes);

        // Handle FAT (Universal) binaries by parsing the first architecture
        if let Some((fat_endianness, is_64)) = match magic_be {
            // TODO: There may be a more elegant way to do this.
            0xCAFEBABE => Some((Endianness::Big, false)),
            0xCAFEBABF => Some((Endianness::Big, true)),
            _ => match magic_le {
                0xCAFEBABE => Some((Endianness::Little, false)),
                0xCAFEBABF => Some((Endianness::Little, true)),
                _ => None,
            },
        } {
            let read_u32 = |off: usize| -> Result<u32, errors::FileParseError> {
                let bytes: [u8; 4] = buffer
                    .get(off..off + 4)
                    .ok_or(errors::FileParseError::BufferOverflow)?
                    .try_into()
                    .map_err(|_| errors::FileParseError::BufferOverflow)?;
                Ok(match fat_endianness {
                    Endianness::Little => u32::from_le_bytes(bytes),
                    Endianness::Big => u32::from_be_bytes(bytes),
                })
            };

            let read_u64 = |off: usize| -> Result<u64, errors::FileParseError> {
                let bytes: [u8; 8] = buffer
                    .get(off..off + 8)
                    .ok_or(errors::FileParseError::BufferOverflow)?
                    .try_into()
                    .map_err(|_| errors::FileParseError::BufferOverflow)?;
                Ok(match fat_endianness {
                    Endianness::Little => u64::from_le_bytes(bytes),
                    Endianness::Big => u64::from_be_bytes(bytes),
                })
            };

            let nfat_arch = read_u32(4)? as usize;
            let arch_size = if is_64 { 32 } else { 20 };
            if nfat_arch == 0 || buffer.len() < 8 + arch_size * nfat_arch {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let offset = if is_64 {
                read_u64(8 + 8)? as usize
            } else {
                read_u32(8 + 8)? as usize
            };
            let size = if is_64 {
                read_u64(8 + 16)? as usize
            } else {
                read_u32(8 + 12)? as usize
            };

            if buffer.len() < offset + size {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let inner = buffer
                .get(offset..offset + size)
                .ok_or(errors::FileParseError::BufferOverflow)?
                .to_vec();
            return MachO::from_buffer(inner);
        }

        let (header_size, endianness) = match magic_le {
            0xFEEDFACE => (28, Endianness::Little), // Mach-O 32-bit LE
            0xFEEDFACF => (32, Endianness::Little), // Mach-O 64-bit LE
            0xCEFAEDFE => (28, Endianness::Big),    // Mach-O 32-bit BE
            0xCFFAEDFE => (32, Endianness::Big),    // Mach-O 64-bit BE
            _ => return Err(errors::FileParseError::InvalidFileFormat),
        };

        if buffer.len() < header_size {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let header = MachHeader::parse(&buffer, endianness)?;

        let load_commands_offset = header_size;

        if buffer.len() < load_commands_offset + header.sizeofcmds.value as usize {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let load_commands = LoadCommand::parse_load_commands(
            &buffer,
            load_commands_offset,
            header.ncmds.value,
            endianness,
        )?;
        let segments = Segment::parse_segments(&buffer, &load_commands, endianness)?;

        Ok(MachO {
            buffer,
            header,
            load_commands,
            segments,
        })
    }
}
