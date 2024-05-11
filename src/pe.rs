use std::fs;
use std::io::{self, Write };

use crate::pe_errors::PeError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32, extract_u64};
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
#[derive(PartialEq, Eq, Debug)]
pub enum PEType {
    PE32,
    PE32Plus,
}

pub enum ImageBase {
    Base32(u32),
    Base64(u64),
}

/// Struct to define a PeFile from attr
pub struct PE {
    pub buffer: Vec<u8>,
    pub entry_point: Field<u32>,
    pub size_of_image: Field<u32>,
    pub number_of_sections: Field<u32>,
    pub sections: Vec<PeSection>, 
    pub checksum: Field<u32>,
    pub architecture: Field<String>,
    pub section_alignment: Field<u32>, 
    pub file_alignment: Field<u32>,  
    pub size_of_headers: Field<u32>,
    pub base_of_code: Field<u32>,
    pub base_of_data: Field<u32>,  
    pub image_base: Field<ImageBase>,
    pub subsystem: Field<u16>,
    pub dll_characteristics: Field<u16>,
    pub pe_type:PEType,
}

impl PE {

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
    /// use hex_spell::pe::parse_from_file;
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
/// use hex_spell::pe::parse_from_file;
/// let pe_file = parse_from_file("tests/samples/sample1.exe").unwrap();
/// ```
pub fn parse_from_file(path:&str) -> Result<PE, PeError> {
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
/// use hex_spell::pe::parse_from_vec;
/// let data = std::fs::read("tests/samples/sample1.exe").expect("Failed to read file");
/// let pe_file = parse_from_vec(data).unwrap();
/// ```
pub fn parse_from_vec(buffer: Vec<u8>) -> Result<PE, PeError> {
    if buffer.len() < 64 || buffer[0] != 0x4D || buffer[1] != 0x5A {
        return Err(PeError::InvalidPeFile);
    }

    let e_lfanew_offset = 0x3C;
    let pe_header_offset = extract_u32(&buffer, e_lfanew_offset)? as usize;

    let optional_header_offset = pe_header_offset + 24; 
    let optional_header_size = extract_u16(&buffer, pe_header_offset + 20)?;
    let sections_offset = optional_header_offset + optional_header_size as usize;
    
    // IMAGE FILE HEADER
    let number_of_sections = extract_u16(&buffer, pe_header_offset + 6)? as u32;
    let architecture = Architecture::from_u16(extract_u16(&buffer, pe_header_offset + 4)?);
    
    let entry_point = extract_u32(&buffer, pe_header_offset + 40)?;
    let size_of_image = extract_u32(&buffer, pe_header_offset + 80)?;
    let checksum = extract_u32(&buffer, pe_header_offset + 88)?;
    
    // OPTIONAL HEADER
    let base_of_code = extract_u32(&buffer, optional_header_offset + 20)?;
    let base_of_data = extract_u32(&buffer, optional_header_offset + 24)?;

    let section_alignment = extract_u32(&buffer, optional_header_offset + 32)?;
    let file_alignment = extract_u32(&buffer, optional_header_offset + 36)?;
    let size_of_headers = extract_u32(&buffer, optional_header_offset + 60)?;
    let subsystem = extract_u16(&buffer, optional_header_offset + 68)?;
    let dll_characteristics = extract_u16(&buffer, optional_header_offset + 70)?;

    let magic = extract_u16(&buffer, optional_header_offset)?;

    let pe_type = match magic {
        0x10B => PEType::PE32,
        0x20B => PEType::PE32Plus,
        _ => return Err(PeError::InvalidPeFile),
    };

    let image_base = match pe_type {
        PEType::PE32 => ImageBase::Base32(extract_u32(&buffer, optional_header_offset + 28)?),
        PEType::PE32Plus => ImageBase::Base64(extract_u64(&buffer, optional_header_offset + 24)?),
    };


    let mut sections = Vec::with_capacity(number_of_sections as usize);
    let mut current_offset = sections_offset;
    for _ in 0..number_of_sections {
        let section = PeSection::parse_section(&buffer, current_offset)?;
        sections.push(section);
        current_offset += 40;
    }

    Ok(PE {
        buffer,
        entry_point: Field::new(entry_point, pe_header_offset + 40, 4),
        size_of_image: Field::new(size_of_image, pe_header_offset + 80, 4),
        number_of_sections: Field::new(number_of_sections, pe_header_offset + 6, 2),
        sections,
        checksum: Field::new(checksum, pe_header_offset + 88, 4),
        architecture: Field::new(architecture.to_string(), pe_header_offset + 4, 2),
        section_alignment: Field::new(section_alignment, optional_header_offset + 32, 4),
        file_alignment: Field::new(file_alignment, optional_header_offset + 36, 4),
        image_base: Field::new(image_base, optional_header_offset + 28,  match pe_type {
            PEType::PE32 => 4,
            PEType::PE32Plus => 8,
        }),
        base_of_code: Field::new(base_of_code, optional_header_offset + 20, 4),
        base_of_data: Field::new(base_of_data, optional_header_offset + 24, 4),
        subsystem: Field::new(subsystem, optional_header_offset + 68, 2),
        dll_characteristics: Field::new(dll_characteristics, optional_header_offset + 70, 2),
        size_of_headers: Field::new(size_of_headers, optional_header_offset + 60, 4),
        pe_type,
    })
}

