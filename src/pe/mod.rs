use std::fs;
use std::io::{self, Write };

use crate::field::Field;
use crate::utils::{extract_u16, extract_u32, extract_u64};
use crate::errors::FileParseError;

pub mod header;
pub mod section;

/// Struct to define a PeFile from attr
pub struct PE {
    pub buffer: Vec<u8>,
    pub header: header::PeHeader,
    pub sections: Vec<section::PeSection>,
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
    /// use hex_spell::pe::PE;
    /// let pe = PE::from_file("tests/samples/sample1.exe").unwrap(); // Sample checksum has to be the correct
    /// let calculed_check:u32 = pe.calc_checksum(); 
    /// assert_eq!(pe.header.checksum.value, calculed_check);
    /// ```
    pub fn calc_checksum(&self) -> u32 {
        let mut checksum: u32 = 0;
        let len = self.buffer.len();
        let mut i = 0;

        while i < len {
            // Skip checksum field  
            if i == self.header.checksum.offset {
                i += self.header.checksum.size;
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


    /// Parses a PE file from a specified file path.
    /// 
    /// # Arguments
    /// * `path` - A string slice that holds the path to the PE file.
    ///
    /// # Returns
    /// A `Result` that is either a `PeFile` on success, or a `FileParseError` on failure.
    /// 
    /// # Example
    /// ```
    /// use hex_spell::pe::PE;
    /// let pe_file = PE::from_file("tests/samples/sample1.exe").unwrap();
    /// ```
    pub fn from_file(path:&str) -> Result<PE, FileParseError> {
        let data: Vec<u8> = fs::read(path).map_err(|e: std::io::Error| FileParseError::Io(e))?;
        PE::from_buffer(data)
    }

    /// Parses a PE file from a byte vector.
    ///
    /// # Arguments
    /// * `buffer` - A byte vector containing the PE file data.
    ///
    /// # Returns
    /// A `Result` that is either a `PeFile` on success, or a `FileParseError` on failure.
    ///
    /// # Example
    /// ```
    /// use hex_spell::pe::PE;
    /// let data = std::fs::read("tests/samples/sample1.exe").expect("Failed to read file");
    /// let pe_file = PE::from_buffer(data).unwrap();
    /// ```
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, FileParseError> {
        if buffer.len() < 64 || buffer[0] != 0x4D || buffer[1] != 0x5A {
            return Err(FileParseError::InvalidFileFormat);
        }

        let e_lfanew_offset = 0x3C;
        let pe_header_offset = extract_u32(&buffer, e_lfanew_offset)? as usize;
        let optional_header_offset = pe_header_offset + 24;
        let optional_header_size = extract_u16(&buffer, pe_header_offset + 20)?;
        let sections_offset = optional_header_offset + optional_header_size as usize;
        let number_of_sections = extract_u16(&buffer, pe_header_offset + 6)?;
        
        let header = header::PeHeader {
            architecture: Field::new(header::Architecture::from_u16(extract_u16(&buffer, pe_header_offset + 4)?).to_string(), pe_header_offset + 4, 2),
            entry_point: Field::new(extract_u32(&buffer, pe_header_offset + 40)?, pe_header_offset + 40, 4),
            size_of_image: Field::new(extract_u32(&buffer, pe_header_offset + 80)?, pe_header_offset + 80, 4),
            number_of_sections: Field::new(number_of_sections, pe_header_offset + 6, 2),
            checksum: Field::new(extract_u32(&buffer, pe_header_offset + 88)?, pe_header_offset + 88, 4),
            file_alignment: Field::new(extract_u32(&buffer, optional_header_offset + 36)?, optional_header_offset + 36, 4),
            section_alignment: Field::new(extract_u32(&buffer, optional_header_offset + 32)?, optional_header_offset + 32, 4),
            base_of_code: Field::new(extract_u32(&buffer, optional_header_offset + 20)?, optional_header_offset + 20, 4),
            base_of_data: Field::new(extract_u32(&buffer, optional_header_offset + 24)?, optional_header_offset + 24, 4),
            image_base: Field::new(match extract_u16(&buffer, optional_header_offset)? {
                0x10B => header::ImageBase::Base32(extract_u32(&buffer, optional_header_offset + 28)?),
                0x20B => header::ImageBase::Base64(extract_u64(&buffer, optional_header_offset + 24)?),
                _ => return Err(FileParseError::InvalidFileFormat),
            }, optional_header_offset + 28, 8),
            subsystem: Field::new(extract_u16(&buffer, optional_header_offset + 68)?, optional_header_offset + 68, 2),
            dll_characteristics: Field::new(extract_u16(&buffer, optional_header_offset + 70)?, optional_header_offset + 70, 2),
            size_of_headers: Field::new(extract_u32(&buffer, optional_header_offset + 60)?, optional_header_offset + 60, 4),
            pe_type: match extract_u16(&buffer, optional_header_offset)? {
                0x10B => header::PEType::PE32,
                0x20B => header::PEType::PE32Plus,
                _ => return Err(FileParseError::InvalidFileFormat),
            },
        };

        let mut sections = Vec::with_capacity(number_of_sections as usize);
        let mut current_offset = sections_offset;
        for _ in 0..number_of_sections {
            let section = section::PeSection::parse_section(&buffer, current_offset)?;
            sections.push(section);
            current_offset += 40;
        }

        Ok(PE { buffer, header, sections })
    }
}



