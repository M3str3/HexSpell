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

    /// Generates a new section WITHOUT adding it to the PE file.
    /// 
    /// # Arguments
    /// * `name` - The name of the new section.
    /// * `size` - The size of the new section.
    /// * `characteristics` - Characteristics of the new section, such as executable and writable flags.
    ///
    /// # Returns
    /// A `Result` containing the new `PeSection` or a `FileParseError`.
    pub fn generate_section_header(&self, name: &str, size: u32, characteristics: u32) -> Result<section::PeSection, FileParseError> {
        let file_alignment = self.header.file_alignment.value;
        let section_alignment = self.header.section_alignment.value;

        // Calculate the new section's virtual and raw addresses and sizes
        let last_section = self.sections.last().ok_or(FileParseError::InvalidFileFormat)?;

        let new_section_offset = last_section.characteristics.offset + last_section.characteristics.size;
        let new_section_rva = (last_section.virtual_address.value + last_section.virtual_size.value + section_alignment - 1) & !(section_alignment - 1);
        let virtual_size = (size + section_alignment - 1) & !(section_alignment - 1);
        let size_of_raw_data = (size + file_alignment - 1) & !(file_alignment - 1);
        let raw_data_ptr = (last_section.pointer_to_raw_data.value + last_section.size_of_raw_data.value + file_alignment - 1) & !(file_alignment - 1);

        let mut name_bytes = [0u8; 8];
        let name_slice = name.as_bytes();
        let len = name_slice.len().min(8);
        name_bytes[..len].copy_from_slice(&name_slice[..len]);

        // Create the new section
        Ok(section::PeSection {
            name: Field::new(String::from_utf8_lossy(&name_bytes).to_string(), new_section_offset, 8),
            virtual_size: Field::new(virtual_size, new_section_offset + 8, 4),
            virtual_address: Field::new(new_section_rva, new_section_offset + 12, 4),
            size_of_raw_data: Field::new(size_of_raw_data, new_section_offset + 16, 4),
            pointer_to_raw_data: Field::new(raw_data_ptr as u32, new_section_offset + 20, 4),
            pointer_to_relocations: Field::new(0, new_section_offset + 24, 4),
            pointer_to_linenumbers: Field::new(0, new_section_offset + 28, 4),
            number_of_relocations: Field::new(0, new_section_offset + 32, 2),
            number_of_linenumbers: Field::new(0, new_section_offset + 34, 2),
            characteristics: Field::new(characteristics, new_section_offset + 36, 4),
        })
    }

    /// Adds a section to the PE file.
    ///
    /// # Arguments
    /// * `new_section` - The new section header to be added.
    /// * `shellcode` - The shellcode or data to be added in the new section.
    ///
    /// # Returns
    /// A `Result` indicating success or failure of the operation.
    pub fn add_section(&mut self, new_section: section::PeSection, shellcode: Vec<u8>) -> Result<(), FileParseError> {
        const SECTION_HEADER_SIZE: usize = 40;

        let raw_data_ptr = new_section.pointer_to_raw_data.value;

        // Create the section header buffer to be inserted
        let mut section_header_buffer = Vec::with_capacity(SECTION_HEADER_SIZE);
        section_header_buffer.extend_from_slice(&new_section.name.value.as_bytes()[..8]);
        section_header_buffer.extend(&new_section.virtual_size.value.to_le_bytes());
        section_header_buffer.extend(&new_section.virtual_address.value.to_le_bytes());
        section_header_buffer.extend(&new_section.size_of_raw_data.value.to_le_bytes());
        section_header_buffer.extend(&new_section.pointer_to_raw_data.value.to_le_bytes());
        section_header_buffer.extend(&new_section.pointer_to_relocations.value.to_le_bytes());
        section_header_buffer.extend(&new_section.pointer_to_linenumbers.value.to_le_bytes());
        section_header_buffer.extend(&new_section.number_of_relocations.value.to_le_bytes());
        section_header_buffer.extend(&new_section.number_of_linenumbers.value.to_le_bytes());
        section_header_buffer.extend(&new_section.characteristics.value.to_le_bytes());

        // Ensure the section header buffer is exactly 40 bytes
        assert_eq!(section_header_buffer.len(), SECTION_HEADER_SIZE);

        // Add the shellcode to the buffer
        if self.buffer.len() < raw_data_ptr as usize + new_section.size_of_raw_data.value as usize {
            self.buffer.resize(raw_data_ptr as usize + new_section.size_of_raw_data.value as usize, 0);
        }
        
        // Inject the new section header
        self.buffer.splice(new_section.name.offset..new_section.name.offset + SECTION_HEADER_SIZE, section_header_buffer.iter().copied());
        // Inject the new code
        self.buffer.splice(raw_data_ptr as usize..raw_data_ptr as usize + shellcode.len(), shellcode.iter().copied());

        // Update headers
        self.header.size_of_image.update(&mut self.buffer, new_section.virtual_address.value + new_section.virtual_size.value);
        self.header.number_of_sections.update(&mut self.buffer, self.header.number_of_sections.value + 1);

        // Add the new section to the PE struct
        self.sections.push(new_section);

        // Calculate and update the checksum
        let new_checksum = self.calc_checksum();
        self.header.checksum.update(&mut self.buffer, new_checksum);

        Ok(())
    }

}



