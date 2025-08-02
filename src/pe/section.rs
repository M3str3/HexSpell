use crate::errors;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

pub enum Characteristics {
    Executable,
    Writeable,
    Readable,
    Code,
    Discardable,
    Tls,
}

impl Characteristics {
    pub fn to_u32(&self) -> u32 {
        match self {
            Characteristics::Executable => 0x20000000u32,
            Characteristics::Writeable => 0x80000000u32,
            Characteristics::Readable => 0x40000000u32,
            Characteristics::Code => 0x00000020u32,
            Characteristics::Discardable => 0x02000000u32,
            Characteristics::Tls => 0x00000400u32,
        }
    }
}

pub struct PeSection {
    pub name: Field<String>,
    pub virtual_size: Field<u32>,
    pub virtual_address: Field<u32>,
    pub size_of_raw_data: Field<u32>,
    pub pointer_to_raw_data: Field<u32>,
    pub pointer_to_relocations: Field<u32>,
    pub pointer_to_linenumbers: Field<u32>,
    pub number_of_relocations: Field<u16>,
    pub number_of_linenumbers: Field<u16>,
    pub characteristics: Field<u32>,
}

impl PeSection {
    /// Checks if the section is executable
    pub fn is_executable(&self) -> bool {
        self.characteristics.value & 0x20000000 != 0
    }

    /// Checks if the section is writable
    pub fn is_writable(&self) -> bool {
        self.characteristics.value & 0x80000000 != 0
    }

    /// Checks if the section is readable
    pub fn is_readable(&self) -> bool {
        self.characteristics.value & 0x40000000 != 0
    }

    /// Checks if the section contains initialized data
    pub fn has_initialized_data(&self) -> bool {
        self.characteristics.value & 0x00000040 != 0
    }

    /// Checks if the section contains uninitialized data
    pub fn has_uninitialized_data(&self) -> bool {
        self.characteristics.value & 0x00000080 != 0
    }

    /// Checks if the section is discardable
    pub fn is_discardable(&self) -> bool {
        self.characteristics.value & 0x02000000 != 0
    }

    /// Checks if the section contains code
    pub fn has_code(&self) -> bool {
        self.characteristics.value & 0x00000020 != 0
    }

    /// Checks if the section contains thread local storage data
    pub fn has_tls(&self) -> bool {
        self.characteristics.value & 0x00000400 != 0
    }

    /// Extracts ascii strings from the section's data based on a specified minimum length.
    ///
    /// # Arguments
    /// * `buffer` - A slice of bytes from the entire PE file's buffer.
    /// * `min_length` - The minimum length a sequence of characters must have to be considered a string.
    ///
    /// # Returns
    /// A vector of strings found within this section that meet or exceed the specified minimum length.
    ///
    /// # Example
    /// ```
    /// use hexspell::pe::PE;
    /// let pe = PE::from_file("tests/samples/sample1.exe").unwrap();
    ///
    /// let strings = pe.sections[0].extract_strings(&pe.buffer, 2).unwrap();
    ///
    /// for s in strings {
    ///     println!("{}", s);
    /// }
    /// ```
    pub fn extract_strings(&self, buffer: &[u8], min_length: usize) -> Result<Vec<String>, errors::FileParseError> {
        let start = self.pointer_to_raw_data.value as usize;
        let end = start + self.size_of_raw_data.value as usize;
        let data = buffer
            .get(start..end)
            .ok_or(errors::FileParseError::BufferOverflow)?;

        let mut strings = Vec::new();
        let mut current_string = Vec::new();

        for &byte in data {
            if byte.is_ascii_alphanumeric() || byte == b'_' {
                current_string.push(byte as char);
            } else {
                if current_string.len() >= min_length {
                    strings.push(current_string.iter().collect());
                }
                current_string.clear();
            }
        }

        if current_string.len() >= min_length {
            strings.push(current_string.iter().collect());
        }

        Ok(strings)
    }

    /// Parses a section of a PE file from the given buffer and offset.
    ///
    /// ## Arguments
    /// * `buffer` - The PE file data slice.
    /// * `offset` - The offset within that buffer where the section header begins.
    ///
    /// ## Returns
    /// A `io::Result` with PeSection
    pub fn parse_section(buffer: &[u8], offset: usize) -> Result<Self, errors::FileParseError> {
        if buffer.len() < offset + 40 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let name = String::from_utf8_lossy(&buffer[offset..offset + 8])
            .trim_end_matches('\0')
            .to_string();
        let virtual_size = extract_u32(buffer, offset + 8)?;
        let virtual_address = extract_u32(buffer, offset + 12)?;
        let size_of_raw_data = extract_u32(buffer, offset + 16)?;
        let pointer_to_raw_data = extract_u32(buffer, offset + 20)?;
        let pointer_to_relocations = extract_u32(buffer, offset + 24)?;
        let pointer_to_linenumbers = extract_u32(buffer, offset + 28)?;
        let number_of_relocations = extract_u16(buffer, offset + 32)?;
        let number_of_linenumbers = extract_u16(buffer, offset + 34)?;
        let characteristics = extract_u32(buffer, offset + 36)?;

        Ok(PeSection {
            name: Field::new(name, offset, 8),
            virtual_size: Field::new(virtual_size, offset + 8, 4),
            virtual_address: Field::new(virtual_address, offset + 12, 4),
            size_of_raw_data: Field::new(size_of_raw_data, offset + 16, 4),
            pointer_to_raw_data: Field::new(pointer_to_raw_data, offset + 20, 4),
            pointer_to_relocations: Field::new(pointer_to_relocations, offset + 24, 4),
            pointer_to_linenumbers: Field::new(pointer_to_linenumbers, offset + 28, 4),
            number_of_relocations: Field::new(number_of_relocations, offset + 32, 2),
            number_of_linenumbers: Field::new(number_of_linenumbers, offset + 34, 2),
            characteristics: Field::new(characteristics, offset + 36, 4),
        })
    }
}
