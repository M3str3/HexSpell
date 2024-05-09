use std::fs;
use std::io::{self, Write };

use crate::pe_errors::PeError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};
use crate::pe_section::PeSection;

enum Architecture {
    X86,
    X64,
    Unknown,
}

impl Architecture {
    fn from_u16(value: u16) -> Self {
        match value {
            0x014c => Architecture::X86,
            0x8664 => Architecture::X64,
            _ => Architecture::Unknown,
        }
    }

    fn to_string(&self) -> String {
        match *self {
            Architecture::X86 => "x86".to_string(),
            Architecture::X64 => "x64".to_string(),
            Architecture::Unknown => "Unknown".to_string(),
        }
    }
}


/// Struct to define a PeFile from attr
pub struct PeFile {
    pub buffer: Vec<u8>,
    pub entry_point: Field<u32>,
    pub size_of_image: Field<u32>,
    pub number_of_sections: Field<u32>,
    pub sections: Vec<PeSection>, 
    pub checksum: Field<u32>,
    pub architecture: Field<String>,
    pub section_alignment: Field<u32>, 
    pub file_alignment: Field<u32>,  
}

impl PeFile {

    /// Write `self.buffer` on file. 
    pub fn write_file(&self, output_path: &str) -> io::Result<()> {
        let mut file: fs::File = fs::File::create(output_path)?;
        file.write_all(&self.buffer)?;
        Ok(())
    }

    /// Calculate the checksum for a PE file, ignoring the checksum field itself
    /// 
    /// # Examples
    /// ```
    /// use hex_spell::pe_file::parse_from_file;
    /// let pe_file = parse_from_file("tests/samples/sample1.exe").unwrap(); // Sample checksum has to be the correct
    /// let calculed_check:u32 = pe_file.calc_checksum(); 
    /// assert_eq!(pe_file.checksum.value, calculed_check);
    /// ```
    pub fn calc_checksum(&self) -> u32 {
        let mut checksum: u32 = 0;
        let len = self.buffer.len();
        let mut i = 0;

        while i < len {
            // Skip checksum field  
            if i == self.checksum.offset {
                i += self.checksum.size;
                continue;
            }
            
            if i + 1 < len {
                let word = u16::from_le_bytes([self.buffer[i], self.buffer[i + 1]]);
                checksum += u32::from(word);
                i += 2;  
            } else {
                checksum += u32::from(self.buffer[i]);
                break;
            }
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum += len as u32;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum
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

    let e_lfanew_offset = 0x3C;
    let pe_header_offset = extract_u32(&buffer, e_lfanew_offset)? as usize;

    let number_of_sections = extract_u16(&buffer, pe_header_offset + 6)? as u32;
    let optional_header_offset = pe_header_offset + 24; 
    let optional_header_size = extract_u16(&buffer, pe_header_offset + 20)?;
    let sections_offset = optional_header_offset + optional_header_size as usize;

    let entry_point = extract_u32(&buffer, pe_header_offset + 40)?;
    let size_of_image = extract_u32(&buffer, pe_header_offset + 80)?;
    let architecture = Architecture::from_u16(extract_u16(&buffer, pe_header_offset + 4)?);
    let checksum = extract_u32(&buffer, pe_header_offset + 88)?;
    let section_alignment = extract_u32(&buffer, optional_header_offset + 32)?;
    let file_alignment = extract_u32(&buffer, optional_header_offset + 36)?;

    let mut sections = Vec::with_capacity(number_of_sections as usize);
    let mut current_offset = sections_offset;
    for _ in 0..number_of_sections {
        let section = PeSection::parse_section(&buffer, current_offset)?;
        sections.push(section);
        current_offset += 40;
    }

    Ok(PeFile {
        buffer,
        entry_point: Field::new(entry_point, pe_header_offset + 40, 4),
        size_of_image: Field::new(size_of_image, pe_header_offset + 80, 4),
        number_of_sections: Field::new(number_of_sections, pe_header_offset + 6, 2),
        sections,
        checksum: Field::new(checksum, pe_header_offset + 88, 4),
        architecture: Field::new(architecture.to_string(), pe_header_offset + 4, 2),
        section_alignment: Field::new(section_alignment, optional_header_offset + 32, 4),
        file_alignment: Field::new(file_alignment, optional_header_offset + 36, 4),
    })
}

