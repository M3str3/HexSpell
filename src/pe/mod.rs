//! Tools for working with the Windows Portable Executable format.
//!
//! The [`PE`](crate::pe::PE) type loads an executable into memory, parses its DOS, COFF, and
//! optional headers, and exposes section information through strongly typed
//! structures. Fields that can be altered are wrapped in [`crate::field::Field`]
//! so the original buffer can be updated in place.
//!
//! In addition to read/modify support, this module offers convenience
//! helpers like [`PE::calc_checksum`](crate::pe::PE::calc_checksum) for computing the file checksum and
//! [`PE::write_file`](crate::pe::PE::write_file) for persisting changes. The implementation is not a
//! complete re-creation of the PE spec but aims to cover the portions
//! commonly needed when experimenting with binaries.

use std::fs;
use std::io::{self, Write};

use crate::errors::FileParseError;
use crate::field::{Field, FixedBytes};

pub mod arch_data;
pub mod bound;
pub mod certificate;
pub mod clr;
pub mod coff;
pub mod debug;
pub mod delay;
pub mod dos;
pub mod exception;
pub mod export;
pub mod header;
pub mod import;
pub mod layout;
pub mod linenum;
pub mod load_config;
pub mod relocation;
pub mod resource;
pub mod rich;
pub mod section;
pub mod section_reloc;
pub mod symbol;
pub mod tls;

/// A parsed PE image backed by an owned byte buffer.
pub struct PE {
    /// Full file contents; pass slices of this to [`crate::field::Field::update`].
    pub buffer: Vec<u8>,
    /// DOS stub header (`IMAGE_DOS_HEADER`).
    pub dos_header: dos::DosHeader,
    /// COFF file header (`IMAGE_FILE_HEADER`).
    pub coff_header: coff::CoffFileHeader,
    /// PE optional header (PE32 or PE32+).
    pub optional_header: header::OptionalHeader,
    /// Section table entries in file order.
    pub sections: Vec<section::PeSection>,
    /// Base relocation blocks from `IMAGE_DIRECTORY_ENTRY_BASERELOC`.
    pub base_relocations: Vec<relocation::BaseRelocationBlock>,
}

impl PE {
    /// Returns the target architecture derived from the COFF `machine` field.
    pub fn architecture(&self) -> header::Architecture {
        self.coff_header.architecture()
    }

    /// Maps a relative virtual address to an absolute file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Result<usize, FileParseError> {
        import::rva_to_offset(&self.buffer, &self.sections, rva)
    }

    /// Read-only view of the import directory (`IMAGE_IMPORT_DESCRIPTOR` array).
    pub fn imports(&self) -> Result<import::ImportDirectory, FileParseError> {
        let import_rva = self.optional_header.data_directories[header::IMPORT]
            .virtual_address
            .value;
        import::ImportDirectory::parse(
            &self.buffer,
            &self.sections,
            import_rva,
            self.optional_header.pe_type()?,
        )
    }

    /// Returns raw on-disk bytes for section `index` (`PointerToRawData` .. `SizeOfRawData`).
    pub fn section_data(&self, index: usize) -> Result<&[u8], FileParseError> {
        let section = self
            .sections
            .get(index)
            .ok_or(FileParseError::BufferOverflow)?;
        let start = section.pointer_to_raw_data.value as usize;
        let end = start
            .checked_add(section.size_of_raw_data.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        self.buffer
            .get(start..end)
            .ok_or(FileParseError::BufferOverflow)
    }

    /// Parses the export data directory when present.
    ///
    /// Returns `Ok(None)` when the export directory RVA is zero.
    pub fn exports(&self) -> Result<Option<export::Exports>, FileParseError> {
        let entry = &self.optional_header.data_directories[header::EXPORT];
        if entry.virtual_address.value == 0 {
            return Ok(None);
        }

        let export_dir_rva = entry.virtual_address.value;
        let export_dir_size = entry.size.value;
        let offset = self.rva_to_offset(export_dir_rva)?;
        let directory = export::ExportDirectory::parse(&self.buffer, offset)?;
        let exports = export::Exports::parse(
            &self.buffer,
            &directory,
            export_dir_rva,
            export_dir_size,
            |rva| self.rva_to_offset(rva),
        )?;

        Ok(Some(exports))
    }

    /// Parses the bound import directory when present.
    pub fn bound_imports(&self) -> Result<Option<bound::BoundImportDirectory>, FileParseError> {
        if !self
            .optional_header
            .has_data_directory(header::BOUND_IMPORT)
        {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::BOUND_IMPORT];
        if entry.virtual_address.value == 0 {
            return Ok(None);
        }
        Ok(Some(bound::BoundImportDirectory::parse(
            &self.buffer,
            &self.sections,
            entry.virtual_address.value,
        )?))
    }

    /// Parses the delay-load import directory when present.
    pub fn delay_imports(&self) -> Result<Option<delay::DelayLoadDirectory>, FileParseError> {
        if !self
            .optional_header
            .has_data_directory(header::DELAY_IMPORT)
        {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::DELAY_IMPORT];
        if entry.virtual_address.value == 0 {
            return Ok(None);
        }
        Ok(Some(delay::DelayLoadDirectory::parse(
            &self.buffer,
            &self.sections,
            entry.virtual_address.value,
            self.optional_header.pe_type()?,
        )?))
    }

    /// Parses the TLS directory when present.
    pub fn tls(&self) -> Result<Option<tls::TlsDirectory>, FileParseError> {
        if !self.optional_header.has_data_directory(header::TLS) {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::TLS];
        if entry.virtual_address.value == 0 {
            return Ok(None);
        }
        let offset = self.rva_to_offset(entry.virtual_address.value)?;
        Ok(Some(tls::TlsDirectory::parse(
            &self.buffer,
            offset,
            self.optional_header.pe_type()?,
        )?))
    }

    /// Parses the exception / runtime function directory when present.
    pub fn exceptions(&self) -> Result<Option<exception::ExceptionDirectory>, FileParseError> {
        if !self.optional_header.has_data_directory(header::EXCEPTION) {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::EXCEPTION];
        if entry.virtual_address.value == 0 || entry.size.value == 0 {
            return Ok(None);
        }
        let offset = self.rva_to_offset(entry.virtual_address.value)?;
        Ok(Some(exception::ExceptionDirectory::parse(
            &self.buffer,
            offset,
            entry.size.value as usize,
        )?))
    }

    /// Parses the debug directory when present.
    pub fn debug_directory(&self) -> Result<Option<debug::DebugDirectory>, FileParseError> {
        if !self.optional_header.has_data_directory(header::DEBUG) {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::DEBUG];
        if entry.virtual_address.value == 0 || entry.size.value == 0 {
            return Ok(None);
        }
        let offset = self.rva_to_offset(entry.virtual_address.value)?;
        Ok(Some(debug::DebugDirectory::parse(
            &self.buffer,
            offset,
            entry.size.value as usize,
        )?))
    }

    /// Parses the load configuration directory when present.
    pub fn load_config(&self) -> Result<Option<load_config::LoadConfigDirectory>, FileParseError> {
        if !self.optional_header.has_data_directory(header::LOAD_CONFIG) {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::LOAD_CONFIG];
        if entry.virtual_address.value == 0 {
            return Ok(None);
        }
        let offset = self.rva_to_offset(entry.virtual_address.value)?;
        Ok(Some(load_config::LoadConfigDirectory::parse(
            &self.buffer,
            offset,
            self.optional_header.pe_type()?,
        )?))
    }

    /// Parses the resource directory tree when present.
    pub fn resources(&self) -> Result<Option<resource::ResourceTree>, FileParseError> {
        if !self.optional_header.has_data_directory(header::RESOURCE) {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::RESOURCE];
        if entry.virtual_address.value == 0 {
            return Ok(None);
        }
        let offset = self.rva_to_offset(entry.virtual_address.value)?;
        Ok(Some(resource::ResourceTree::parse(
            &self.buffer,
            offset,
            |rva| self.rva_to_offset(rva),
        )?))
    }

    /// Parses the COFF symbol table referenced by the file header.
    pub fn coff_symbols(&self) -> Result<symbol::CoffSymbolTable, FileParseError> {
        symbol::CoffSymbolTable::parse(
            &self.buffer,
            self.coff_header.pointer_to_symbol_table.value,
            self.coff_header.number_of_symbols.value,
        )
    }

    /// Parses COFF relocations attached to section `index`.
    pub fn section_relocations(
        &self,
        index: usize,
    ) -> Result<section_reloc::SectionRelocationBlock, FileParseError> {
        let section = self
            .sections
            .get(index)
            .ok_or(FileParseError::BufferOverflow)?;
        section_reloc::SectionRelocationBlock::parse(&self.buffer, index, section)
    }

    /// Parses COFF line numbers attached to section `index`.
    pub fn section_linenumbers(
        &self,
        index: usize,
    ) -> Result<linenum::LineNumberBlock, FileParseError> {
        let section = self
            .sections
            .get(index)
            .ok_or(FileParseError::BufferOverflow)?;
        linenum::LineNumberBlock::parse(&self.buffer, index, section)
    }

    /// Parses the Rich header between the DOS stub and PE signature when present.
    pub fn rich_header(&self) -> Result<Option<rich::RichHeader>, FileParseError> {
        rich::RichHeader::parse(&self.buffer, self.dos_header.e_lfanew.value as usize)
    }

    /// Parses the Authenticode certificate table when present (read-only overlay).
    pub fn certificates(&self) -> Result<Option<certificate::CertificateTable>, FileParseError> {
        if !self.optional_header.has_data_directory(header::SECURITY) {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::SECURITY];
        if entry.virtual_address.value == 0 || entry.size.value == 0 {
            return Ok(None);
        }
        Ok(Some(certificate::CertificateTable::parse(
            &self.buffer,
            entry.virtual_address.value,
            entry.size.value,
        )?))
    }

    /// Parses the CLR `IMAGE_COR20_HEADER` when the COM descriptor directory is present.
    pub fn clr(&self) -> Result<Option<clr::Cor20Header>, FileParseError> {
        if !self
            .optional_header
            .has_data_directory(header::COM_DESCRIPTOR)
        {
            return Ok(None);
        }
        let entry = &self.optional_header.data_directories[header::COM_DESCRIPTOR];
        if entry.virtual_address.value == 0 {
            return Ok(None);
        }
        let offset = self.rva_to_offset(entry.virtual_address.value)?;
        Ok(Some(clr::Cor20Header::parse(&self.buffer, offset)?))
    }

    /// Inspects architecture-specific metadata (ARM64x, CHPE, architecture directory).
    pub fn architecture_data(&self) -> Result<arch_data::ArchitectureData, FileParseError> {
        let arch_dir = &self.optional_header.data_directories[header::ARCHITECTURE];
        let (hybrid_meta, chpe_meta) =
            if self.optional_header.has_data_directory(header::LOAD_CONFIG) {
                let lc = &self.optional_header.data_directories[header::LOAD_CONFIG];
                if lc.virtual_address.value != 0 {
                    let offset = self.rva_to_offset(lc.virtual_address.value)?;
                    let size = self
                        .load_config()
                        .ok()
                        .flatten()
                        .map(|cfg| cfg.size.value)
                        .unwrap_or(0);
                    match arch_data::HybridLoadConfigFields::parse(
                        &self.buffer,
                        offset,
                        size,
                        self.coff_header.machine.value,
                        self.optional_header.pe_type()?,
                    ) {
                        Ok(fields) => {
                            let pointer = fields.hybrid_metadata_pointer.map(|f| f.value);
                            (pointer, pointer)
                        }
                        Err(_) => (None, None),
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

        arch_data::ArchitectureData::parse(
            &self.buffer,
            &self.coff_header,
            arch_dir,
            hybrid_meta,
            chpe_meta,
            |rva| self.rva_to_offset(rva),
        )
    }

    /// Updates a data directory RVA in the optional header and buffer.
    pub fn sync_data_directory_rva(
        &mut self,
        index: usize,
        new_rva: u32,
    ) -> Result<(), FileParseError> {
        let entry = self
            .optional_header
            .data_directories
            .get_mut(index)
            .ok_or(FileParseError::BufferOverflow)?;
        entry.virtual_address.update(&mut self.buffer, new_rva)
    }

    /// Updates a data directory size in the optional header and buffer.
    pub fn sync_data_directory_size(
        &mut self,
        index: usize,
        new_size: u32,
    ) -> Result<(), FileParseError> {
        let entry = self
            .optional_header
            .data_directories
            .get_mut(index)
            .ok_or(FileParseError::BufferOverflow)?;
        entry.size.update(&mut self.buffer, new_size)
    }

    /// Updates the preferred image base and applies base relocations.
    pub fn apply_image_base(&mut self, new_base: header::ImageBase) -> Result<(), FileParseError> {
        let pe_type = self.optional_header.pe_type()?;
        let old_base = match self.optional_header.image_base.value {
            header::ImageBase::Base32(value) => value as u64,
            header::ImageBase::Base64(value) => value,
        };
        let new_base_value = match new_base {
            header::ImageBase::Base32(value) => value as u64,
            header::ImageBase::Base64(value) => value,
        };

        relocation::apply_base_relocations(
            &mut self.buffer,
            &self.base_relocations,
            &self.sections,
            old_base,
            new_base_value,
            pe_type,
        )?;

        self.optional_header
            .image_base
            .update(&mut self.buffer, new_base)?;

        Ok(())
    }

    /// Writes [`PE::buffer`] to `output_path`.
    pub fn write_file(&self, output_path: &str) -> io::Result<()> {
        let mut file: fs::File = fs::File::create(output_path)?;
        file.write_all(&self.buffer)?;
        Ok(())
    }

    /// Calculate the checksum for a PE file, ignoring the checksum field itself
    ///
    /// # Examples
    /// ```
    /// use hexspell::pe::PE;
    /// let pe = PE::from_file("tests/samples/sample1.exe").unwrap(); // Sample checksum has to be the correct
    /// let calculed_check:u32 = pe.calc_checksum();
    /// assert_eq!(pe.optional_header.checksum.value, calculed_check);
    /// ```
    pub fn calc_checksum(&self) -> u32 {
        let mut checksum: u64 = 0;
        let len = self.buffer.len();
        let mut i = 0;

        while i < len {
            // Skip checksum field
            if i == self.optional_header.checksum.offset {
                i += self.optional_header.checksum.size;
                continue;
            }

            if i + 1 < len {
                let word = u16::from_le_bytes([self.buffer[i], self.buffer[i + 1]]);
                checksum += word as u64;
                i += 2;
            } else {
                checksum += self.buffer[i] as u64;
                break;
            }
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum += len as u64;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum as u32
    }

    /// Reads and parses a PE file from disk.
    pub fn from_file(path: &str) -> Result<PE, FileParseError> {
        let data: Vec<u8> = fs::read(path).map_err(|e: std::io::Error| FileParseError::Io(e))?;
        PE::from_buffer(data)
    }

    /// Parses a PE image from an owned byte buffer.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, FileParseError> {
        let dos_header = dos::DosHeader::parse(&buffer)?;
        let pe_header_offset = dos_header.e_lfanew.value as usize;

        if buffer.len() < pe_header_offset + 24
            || &buffer[pe_header_offset..pe_header_offset + 4] != b"PE\0\0"
        {
            return Err(FileParseError::InvalidFileFormat);
        }

        let coff_offset = pe_header_offset + 4;
        let coff_header = coff::CoffFileHeader::parse(&buffer, coff_offset)?;
        let optional_header_offset = coff_offset + 20;
        let optional_header_size = coff_header.size_of_optional_header.value as usize;
        let sections_offset = optional_header_offset + optional_header_size;
        let number_of_sections = coff_header.number_of_sections.value;

        if buffer.len() < optional_header_offset + optional_header_size {
            return Err(FileParseError::BufferOverflow);
        }

        let optional_header = header::OptionalHeader::parse(&buffer, optional_header_offset)?;

        let mut sections = Vec::with_capacity(number_of_sections as usize);
        let mut current_offset = sections_offset;
        for _ in 0..number_of_sections {
            let section = section::PeSection::parse_section(&buffer, current_offset)?;
            sections.push(section);
            current_offset += 40;
        }

        let base_relocations = if optional_header.number_of_rva_and_sizes.value
            > header::BASERELOC as u32
        {
            let directory = &optional_header.data_directories[header::BASERELOC];
            if directory.virtual_address.value == 0 || directory.size.value == 0 {
                Vec::new()
            } else {
                let offset =
                    import::rva_to_offset(&buffer, &sections, directory.virtual_address.value)?;
                relocation::parse_base_relocations(&buffer, offset, directory.size.value as usize)?
            }
        } else {
            Vec::new()
        };

        Ok(PE {
            buffer,
            dos_header,
            coff_header,
            optional_header,
            sections,
            base_relocations,
        })
    }

    fn build_section_header(
        &self,
        name: &str,
        size: u32,
        characteristics: u32,
    ) -> Result<section::PeSection, FileParseError> {
        let file_alignment = self.optional_header.file_alignment.value;
        let section_alignment = self.optional_header.section_alignment.value;

        let last_section = self
            .sections
            .last()
            .ok_or(FileParseError::InvalidFileFormat)?;

        let new_section_offset =
            last_section.characteristics.offset + last_section.characteristics.size;
        let new_section_rva = (last_section.virtual_address.value
            + last_section.virtual_size.value
            + section_alignment
            - 1)
            & !(section_alignment - 1);
        let virtual_size = (size + section_alignment - 1) & !(section_alignment - 1);
        let size_of_raw_data = (size + file_alignment - 1) & !(file_alignment - 1);
        let raw_data_ptr = (last_section.pointer_to_raw_data.value
            + last_section.size_of_raw_data.value
            + file_alignment
            - 1)
            & !(file_alignment - 1);

        let mut name_bytes = [0u8; 8];
        let name_slice = name.as_bytes();
        let len = name_slice.len().min(8);
        name_bytes[..len].copy_from_slice(&name_slice[..len]);

        Ok(section::PeSection {
            name: Field::new(FixedBytes(name_bytes), new_section_offset, 8),
            virtual_size: Field::new(virtual_size, new_section_offset + 8, 4),
            virtual_address: Field::new(new_section_rva, new_section_offset + 12, 4),
            size_of_raw_data: Field::new(size_of_raw_data, new_section_offset + 16, 4),
            pointer_to_raw_data: Field::new(raw_data_ptr, new_section_offset + 20, 4),
            pointer_to_relocations: Field::new(0, new_section_offset + 24, 4),
            pointer_to_linenumbers: Field::new(0, new_section_offset + 28, 4),
            number_of_relocations: Field::new(0, new_section_offset + 32, 2),
            number_of_linenumbers: Field::new(0, new_section_offset + 34, 2),
            characteristics: Field::new(characteristics, new_section_offset + 36, 4),
        })
    }

    /// Inserts a section described by [`section::NewSection`], updating headers and checksum.
    pub fn insert_section(
        &mut self,
        new: section::NewSection,
    ) -> Result<&section::PeSection, FileParseError> {
        let section_header =
            self.build_section_header(&new.name, new.data.len() as u32, new.characteristics)?;
        self.insert_section_raw(section_header, new.data)?;
        Ok(self.sections.last().expect("section just pushed"))
    }

    /// Inserts a pre-built [`section::PeSection`] header and raw section data.
    pub fn insert_section_raw(
        &mut self,
        new_section: section::PeSection,
        data: Vec<u8>,
    ) -> Result<(), FileParseError> {
        self.insert_section_impl(new_section, data)
    }

    fn insert_section_impl(
        &mut self,
        new_section: section::PeSection,
        shellcode: Vec<u8>,
    ) -> Result<(), FileParseError> {
        const SECTION_HEADER_SIZE: usize = 40;

        if new_section.characteristics.offset + new_section.characteristics.size
            > self.optional_header.size_of_headers.value as usize
        {
            let new_size_of_headers =
                self.optional_header.size_of_headers.value + SECTION_HEADER_SIZE as u32;

            let alig_new_size_of_headers =
                (new_size_of_headers + self.optional_header.file_alignment.value - 1)
                    & !(self.optional_header.file_alignment.value - 1);
            let alig_old_size_of_headers = self.optional_header.size_of_headers.value;

            if alig_new_size_of_headers != alig_old_size_of_headers {
                self.optional_header
                    .size_of_headers
                    .update(&mut self.buffer, alig_new_size_of_headers)?;

                let diff = alig_new_size_of_headers as usize - alig_old_size_of_headers as usize;

                if diff > 0 {
                    self.buffer.splice(
                        alig_old_size_of_headers as usize..alig_old_size_of_headers as usize,
                        std::iter::repeat_n(0, diff),
                    );

                    for section in self.sections.iter_mut() {
                        section.pointer_to_raw_data.update(
                            &mut self.buffer,
                            section.pointer_to_raw_data.value + diff as u32,
                        )?;
                    }
                }
            }
        }

        let raw_data_ptr = new_section.pointer_to_raw_data.value;
        let new_total_buffer_size =
            raw_data_ptr as usize + new_section.size_of_raw_data.value as usize;
        if self.buffer.len() < new_total_buffer_size {
            self.buffer.resize(new_total_buffer_size, 0);
        }

        let mut section_header_buffer = Vec::with_capacity(SECTION_HEADER_SIZE);
        section_header_buffer.extend_from_slice(&new_section.name.value.0);
        section_header_buffer.extend(&new_section.virtual_size.value.to_le_bytes());
        section_header_buffer.extend(&new_section.virtual_address.value.to_le_bytes());
        section_header_buffer.extend(&new_section.size_of_raw_data.value.to_le_bytes());
        section_header_buffer.extend(&new_section.pointer_to_raw_data.value.to_le_bytes());
        section_header_buffer.extend(&new_section.pointer_to_relocations.value.to_le_bytes());
        section_header_buffer.extend(&new_section.pointer_to_linenumbers.value.to_le_bytes());
        section_header_buffer.extend(&new_section.number_of_relocations.value.to_le_bytes());
        section_header_buffer.extend(&new_section.number_of_linenumbers.value.to_le_bytes());
        section_header_buffer.extend(&new_section.characteristics.value.to_le_bytes());

        self.buffer.splice(
            new_section.name.offset..new_section.name.offset + SECTION_HEADER_SIZE,
            section_header_buffer.iter().copied(),
        );

        self.buffer.splice(
            raw_data_ptr as usize..raw_data_ptr as usize + shellcode.len(),
            shellcode.iter().copied(),
        );

        let new_size_of_image = (new_section.virtual_address.value
            + new_section.virtual_size.value
            + self.optional_header.section_alignment.value
            - 1)
            & !(self.optional_header.section_alignment.value - 1);
        self.optional_header
            .size_of_image
            .update(&mut self.buffer, new_size_of_image)?;

        self.coff_header.number_of_sections.update(
            &mut self.buffer,
            self.coff_header.number_of_sections.value + 1,
        )?;

        self.sections.push(new_section);

        let new_checksum = self.calc_checksum();
        self.optional_header
            .checksum
            .update(&mut self.buffer, new_checksum)?;

        Ok(())
    }
}
