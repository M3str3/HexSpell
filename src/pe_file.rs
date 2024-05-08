use std::fs;
use std::io::{self, Write };
use std::convert::TryInto;

use crate::pe_errors::PeError;

use crate::field::Field;
use crate::pe_section::PeSection;

/// Strutc to define a PeFile from attr
pub struct PeFile {
    pub buffer: Vec<u8>,
    pub entry_point: Field<u32>,
    pub size_of_image: Field<u32>,
    pub number_of_sections: Field<u32>,
    pub sections: Vec<PeSection>, 
    pub checksum: Field<u32>,
    pub architecture: Field<String>,
}

impl PeFile {

    /// Write `self.buffer` on file. 
    pub fn write_file(&self, output_path: &str) -> io::Result<()> {
        let mut file: fs::File = fs::File::create(output_path)?;
        file.write_all(&self.buffer)?;
        Ok(())
    }

}

///------
/// UTILS
/// -----

/// Parses a PE file from a specified file path.
/// 
/// # Arguments
/// * `path` - A string slice that holds the path to the PE file.
///
/// # Returns
/// A `Result` that is either a `PeFile` on success, or a `PeError` on failure.
/// 
/// # Example
/// ```
/// use hex_spell::pe_file::parse_from_file;
/// let pe_file = parse_from_file("tests/samples/sample1.exe").unwrap();
/// ```
pub fn parse_from_file(path:&str) -> Result<PeFile, PeError> {
    let data: Vec<u8> = fs::read(path).map_err(|e: std::io::Error| PeError::Io(e))?;
    parse_from_vec(data)
}

/// Parses a PE file from a byte vector.
///
/// # Arguments
/// * `buffer` - A byte vector containing the PE file data.
///
/// # Returns
/// A `Result` that is either a `PeFile` on success, or a `PeError` on failure.
///
/// # Example
/// ```
/// use hex_spell::pe_file::parse_from_vec;
/// let data = std::fs::read("tests/samples/sample1.exe").expect("Failed to read file");
/// let pe_file = parse_from_vec(data).unwrap();
/// ```
pub fn parse_from_vec(buffer: Vec<u8>) -> Result<PeFile, PeError> {
    if buffer.len() < 64 || buffer[0] != 0x4D || buffer[1] != 0x5A {
        return Err(PeError::InvalidPeFile);
    }

    // Helper function to extract u32 from buffer safely
    fn extract_u32(buffer: &[u8], offset: usize) -> Result<u32, PeError> {
        buffer.get(offset..offset + 4)
            .ok_or(PeError::BufferOverflow)
            .and_then(|bytes| bytes.try_into()
                      .map_err(|_| PeError::BufferOverflow)
                      .and_then(|bytes| Ok(u32::from_le_bytes(bytes))))
    }

    let e_lfanew_offset: usize = 0x3C;
    let pe_header_offset: usize = extract_u32(&buffer, e_lfanew_offset)? as usize;

    let signature_offset: usize = pe_header_offset;
    if signature_offset + 24 > buffer.len() {
        return Err(PeError::BufferOverflow);
    }

    let file_header_offset: usize = signature_offset + 4;
    let number_of_sections: u32 = u16::from_le_bytes(
        buffer.get(file_header_offset + 2..file_header_offset + 4)
              .ok_or(PeError::BufferOverflow)?.try_into()?) as u32;

    let optional_header_size: u16 = u16::from_le_bytes(
        buffer.get(file_header_offset + 16..file_header_offset + 18)
              .ok_or(PeError::BufferOverflow)?.try_into()?);

    let sections_offset: usize = file_header_offset + 20 + optional_header_size as usize;
    if sections_offset > buffer.len() {
        return Err(PeError::BufferOverflow);
    }

    let entry_point: u32 = extract_u32(&buffer, pe_header_offset + 40)?;
    let size_of_image: u32 = extract_u32(&buffer, pe_header_offset + 80)?;

    let architecture: String = match u16::from_le_bytes(
        buffer.get(pe_header_offset + 4..pe_header_offset + 6)
              .ok_or(PeError::BufferOverflow)?.try_into()?) {
        0x014c => "x86",
        0x8664 => "x64",
        _ => "Unknown",
    }.to_string();

    let checksum: u32 = extract_u32(&buffer, pe_header_offset + 88)?;

    let mut sections: Vec<PeSection> = Vec::with_capacity(number_of_sections as usize);
    let mut current_offset: usize = sections_offset;
    for _ in 0..number_of_sections {
        if current_offset + 40 > buffer.len() {
            return Err(PeError::BufferOverflow);
        }
        let section: PeSection = PeSection::parse_section(&buffer, current_offset)?;
        sections.push(section);
        current_offset += 40;
    }

    Ok(PeFile {
        buffer,
        entry_point: Field{
            value: entry_point, offset: pe_header_offset + 40, size: 4
        },
        size_of_image: Field{
            value: size_of_image, offset: pe_header_offset + 80, size: 4
        },
        number_of_sections: Field{
            value: number_of_sections, offset: file_header_offset + 2, size: 2
        },
        sections,
        checksum: Field{
            value: checksum, offset: pe_header_offset + 88, size: 4
        },
        architecture: Field{
            value: architecture, offset: pe_header_offset + 6, size: 2
        }
    })
}
