pub mod header;
pub mod section;
pub mod program;

use std::fs;
use std::io::Read;
use crate::errors;

use header::ElfHeader;
use program::ProgramHeader;
use section::SectionHeader;

pub struct ELF {
    pub buffer: Vec<u8>,
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
}

impl ELF {
    /// Parses a ELF file from a specified file path.
    /// 
    /// # Arguments
    /// * `path` - A string slice that holds the path to the PE file.
    ///
    /// # Returns
    /// A `Result` that is either a `ELF` on success, or a `FileParseError` on failure.
    /// 
    /// # Example
    /// ```
    /// use hexspell::elf::ELF;
    /// let elf_file = ELF::from_file("tests/samples/linux").unwrap();
    /// ```
    pub fn from_file(path: &str) -> Result<Self, errors::FileParseError> {
        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Self::from_buffer(buffer)
    }

    /// Parses a ELF file from a byte vector.
    ///
    /// # Arguments
    /// * `buffer` - A byte vector containing the ELF file data.
    ///
    /// # Returns
    /// A `Result` that is either a `ELF` on success, or a `FileParseError` on failure.
    ///
    /// # Example
    /// ```
    /// use hexspell::elf::ELF;
    /// let data = std::fs::read("tests/samples/linux").expect("Failed to read file");
    /// let elf_file = ELF::from_buffer(data).unwrap();
    /// ```
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 64 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let header = ElfHeader::parse(&buffer)?;
        let program_headers = ProgramHeader::parse_program_headers(&buffer, header.ph_off.value, header.ph_ent_size.value, header.ph_num.value)?;
        let section_headers = SectionHeader::parse_section_headers(&buffer, header.sh_off.value, header.sh_ent_size.value, header.sh_num.value)?;

        Ok(ELF { buffer, header, program_headers, section_headers })
    }
}
