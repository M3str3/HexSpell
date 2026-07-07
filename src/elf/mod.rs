//! Utilities for parsing and rewriting ELF binaries.
//!
//! Load a file with [`ELF::from_file`], patch fields through [`crate::field::Field`] or the
//! `p_*()` / `p_*_mut()` accessors on [`ProgramHeaderEntry`], then persist with
//! [`ELF::write_file`]. Endianness is defined by [`ElfHeader::ei_data`]; use
//! [`ELF::byte_order`] as a convenience.
//!
//! Beyond the header tables, linked structures are parsed on demand: section names via
//! [`ELF::section_name`], symbol tables via [`ELF::symbols`] / [`ELF::dynamic_symbols`], the
//! dynamic array via [`ELF::dynamic`], and relocations via [`ELF::relocations`]. Parsing is
//! read-only; every field is exposed as a [`crate::field::Field`] with its real file offset.

pub mod archive;
pub mod dynamic;
pub mod group;
pub mod hash;
pub mod header;
pub mod link;
pub mod note;
pub mod program;
pub mod relocation;
pub mod section;
pub mod symbol;
pub mod unwind;
pub mod version;

use crate::errors;
use crate::field::ByteOrder;
use archive::Archive;
use header::{ElfClass, ElfHeader};
use program::{NewPtLoad, ProgramHeaderEntry, PT_LOAD};
use section::{NewSection, SectionHeaderEntry};

/// Reads a NUL-terminated string starting at `offset` in a string table region.
///
/// Used to resolve `.shstrtab`, `.strtab` and `.dynstr` names. Invalid UTF-8 is decoded lossily.
pub(crate) fn read_str_at(buffer: &[u8], offset: usize) -> Result<String, errors::FileParseError> {
    let tail = buffer
        .get(offset..)
        .ok_or(errors::FileParseError::BufferOverflow)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(errors::FileParseError::InvalidFileFormat)?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// A parsed ELF image backed by an owned byte buffer.
pub struct ELF {
    /// Full file contents; pass slices of this to field update methods.
    pub buffer: Vec<u8>,
    /// ELF file header (`Ehdr`).
    pub header: ElfHeader,
    /// Program header table (`Phdr`).
    pub program_headers: Vec<ProgramHeaderEntry>,
    /// Section header table (`Shdr`).
    pub section_headers: Vec<SectionHeaderEntry>,
}

impl ELF {
    /// Endianness from `header.ei_data` (`1` = little, `2` = big).
    pub fn byte_order(&self) -> Result<ByteOrder, errors::FileParseError> {
        ByteOrder::from_ei_data(self.header.ei_data.value)
    }

    /// Resolves the name of section `index` via the section header string table (`.shstrtab`).
    pub fn section_name(&self, index: usize) -> Result<String, errors::FileParseError> {
        let sh = self
            .section_headers
            .get(index)
            .ok_or(errors::FileParseError::BufferOverflow)?;
        let strndx = self.header.sh_strndx.value as usize;
        let strtab = self
            .section_headers
            .get(strndx)
            .ok_or(errors::FileParseError::InvalidFileFormat)?;
        let name_offset = strtab.sh_offset() as usize + sh.sh_name() as usize;
        read_str_at(&self.buffer, name_offset)
    }

    /// Returns the raw on-disk bytes of section `index` (`sh_offset` .. `sh_offset + sh_size`).
    ///
    /// `SHT_NOBITS` sections (e.g. `.bss`) occupy no file space and yield an empty slice.
    pub fn section_data(&self, index: usize) -> Result<&[u8], errors::FileParseError> {
        let sh = self
            .section_headers
            .get(index)
            .ok_or(errors::FileParseError::BufferOverflow)?;
        if sh.sh_type() == section::SHT_NOBITS {
            return Ok(&[]);
        }
        let start = sh.sh_offset() as usize;
        let end = start
            .checked_add(sh.sh_size() as usize)
            .ok_or(errors::FileParseError::BufferOverflow)?;
        self.buffer
            .get(start..end)
            .ok_or(errors::FileParseError::BufferOverflow)
    }

    /// Finds the index of the first section named `name`.
    pub fn section_index_by_name(&self, name: &str) -> Option<usize> {
        (0..self.section_headers.len())
            .find(|&i| self.section_name(i).map(|n| n == name).unwrap_or(false))
    }

    /// Finds the first section header named `name`.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeaderEntry> {
        self.section_index_by_name(name)
            .map(|i| &self.section_headers[i])
    }

    /// Returns the raw bytes of section `name`, if it exists.
    pub fn section_data_by_name(
        &self,
        name: &str,
    ) -> Result<Option<&[u8]>, errors::FileParseError> {
        match self.section_index_by_name(name) {
            Some(index) => Ok(Some(self.section_data(index)?)),
            None => Ok(None),
        }
    }

    /// Maps a virtual address to a file offset through `PT_LOAD` segments.
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        self.program_headers
            .iter()
            .filter(|ph| ph.p_type() == program::PT_LOAD)
            .find_map(|ph| {
                let start = ph.p_vaddr();
                let end = start.checked_add(ph.p_filesz())?;
                if va >= start && va < end {
                    Some(ph.p_offset() + (va - start))
                } else {
                    None
                }
            })
    }

    /// Lists conventional PLT/GOT sections with their `sh_link` and `sh_addr` values.
    pub fn plt_got_sections(&self) -> Vec<link::LinkedSection> {
        [".plt", ".plt.got", ".got", ".got.plt"]
            .iter()
            .filter_map(|role| {
                let section_index = self.section_index_by_name(role)?;
                let sh = &self.section_headers[section_index];
                Some(link::LinkedSection {
                    role: (*role).to_string(),
                    section_index,
                    link: sh.sh_link(),
                    addr: sh.sh_addr(),
                })
            })
            .collect()
    }

    /// Parses `.hash`, if present.
    pub fn sysv_hash(&self) -> Result<Option<hash::SysvHashTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let Some(index) = self.section_index_by_name(".hash") else {
            return Ok(None);
        };
        let sh = &self.section_headers[index];
        Ok(Some(hash::SysvHashTable::parse(
            &self.buffer,
            sh.sh_offset() as usize,
            order,
        )?))
    }

    /// Parses `.gnu.hash`, if present.
    pub fn gnu_hash(&self) -> Result<Option<hash::GnuHashTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;
        let Some(index) = self.section_index_by_name(".gnu.hash") else {
            return Ok(None);
        };
        let sh = &self.section_headers[index];
        let word_size = match class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        Ok(Some(hash::GnuHashTable::parse(
            &self.buffer,
            sh.sh_offset() as usize,
            sh.sh_size() as usize,
            word_size,
            order,
        )?))
    }

    /// Parses `.gnu.version`, if present.
    pub fn version_symbols(
        &self,
    ) -> Result<Option<version::VersionSymbolTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let Some(index) = self.section_index_by_name(".gnu.version") else {
            return Ok(None);
        };
        let sh = &self.section_headers[index];
        Ok(Some(version::VersionSymbolTable::parse(
            &self.buffer,
            sh.sh_offset() as usize,
            sh.sh_size() as usize,
            order,
        )?))
    }

    /// Parses `.gnu.version_r`, if present.
    pub fn version_needs(
        &self,
    ) -> Result<Option<version::VersionNeedTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let Some(index) = self.section_index_by_name(".gnu.version_r") else {
            return Ok(None);
        };
        let sh = &self.section_headers[index];
        Ok(Some(version::VersionNeedTable::parse(
            &self.buffer,
            sh.sh_offset() as usize,
            sh.sh_size() as usize,
            order,
        )?))
    }

    /// Parses `.gnu.version_d`, if present.
    pub fn version_defs(&self) -> Result<Option<version::VersionDefTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let Some(index) = self.section_index_by_name(".gnu.version_d") else {
            return Ok(None);
        };
        let sh = &self.section_headers[index];
        Ok(Some(version::VersionDefTable::parse(
            &self.buffer,
            sh.sh_offset() as usize,
            sh.sh_size() as usize,
            order,
        )?))
    }

    /// Returns `.eh_frame` bytes, if present.
    pub fn eh_frame(&self) -> Result<Option<unwind::SectionBlob<'_>>, errors::FileParseError> {
        self.named_blob(".eh_frame")
    }

    /// Parses `.eh_frame_hdr`, if present.
    pub fn eh_frame_hdr(&self) -> Result<Option<unwind::EhFrameHdr>, errors::FileParseError> {
        let Some(index) = self.section_index_by_name(".eh_frame_hdr") else {
            return Ok(None);
        };
        let sh = &self.section_headers[index];
        Ok(Some(unwind::EhFrameHdr::parse(
            &self.buffer,
            sh.sh_offset() as usize,
            sh.sh_size() as usize,
        )?))
    }

    /// Returns `.gcc_except_table` bytes, if present.
    pub fn gcc_except_table(
        &self,
    ) -> Result<Option<unwind::SectionBlob<'_>>, errors::FileParseError> {
        self.named_blob(".gcc_except_table")
    }

    /// Parses all `SHT_NOTE` sections.
    pub fn note_sections(&self) -> Result<Vec<(usize, note::NoteTable)>, errors::FileParseError> {
        let order = self.byte_order()?;
        let mut notes = Vec::new();
        for (index, sh) in self.section_headers.iter().enumerate() {
            if sh.sh_type() == section::SHT_NOTE {
                notes.push((
                    index,
                    note::NoteTable::parse(
                        &self.buffer,
                        sh.sh_offset() as usize,
                        sh.sh_size() as usize,
                        order,
                    )?,
                ));
            }
        }
        Ok(notes)
    }

    /// Parses all `PT_NOTE` segments.
    pub fn note_segments(&self) -> Result<Vec<(usize, note::NoteTable)>, errors::FileParseError> {
        let order = self.byte_order()?;
        let mut notes = Vec::new();
        for (index, ph) in self.program_headers.iter().enumerate() {
            if ph.p_type() == program::PT_NOTE {
                notes.push((
                    index,
                    note::NoteTable::parse(
                        &self.buffer,
                        ph.p_offset() as usize,
                        ph.p_filesz() as usize,
                        order,
                    )?,
                ));
            }
        }
        Ok(notes)
    }

    /// Returns GNU property notes from `.note.gnu.property` or `PT_GNU_PROPERTY`.
    pub fn gnu_property_notes(&self) -> Result<Vec<note::NoteTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let mut notes = Vec::new();
        if let Some(index) = self.section_index_by_name(".note.gnu.property") {
            let sh = &self.section_headers[index];
            notes.push(note::NoteTable::parse(
                &self.buffer,
                sh.sh_offset() as usize,
                sh.sh_size() as usize,
                order,
            )?);
        }
        for ph in self
            .program_headers
            .iter()
            .filter(|ph| ph.p_type() == program::PT_GNU_PROPERTY)
        {
            notes.push(note::NoteTable::parse(
                &self.buffer,
                ph.p_offset() as usize,
                ph.p_filesz() as usize,
                order,
            )?);
        }
        Ok(notes)
    }

    /// Parses all `SHT_GROUP` sections.
    pub fn section_groups(&self) -> Result<Vec<group::SectionGroup>, errors::FileParseError> {
        let order = self.byte_order()?;
        let mut groups = Vec::new();
        for (index, sh) in self.section_headers.iter().enumerate() {
            if sh.sh_type() == section::SHT_GROUP {
                groups.push(group::SectionGroup::parse(
                    &self.buffer,
                    sh.sh_offset() as usize,
                    sh.sh_size() as usize,
                    index,
                    order,
                )?);
            }
        }
        Ok(groups)
    }

    /// Parses `.init_array`, if present.
    pub fn init_array(&self) -> Result<Option<unwind::AddressArray>, errors::FileParseError> {
        self.address_array_by_name(".init_array")
    }

    /// Parses `.fini_array`, if present.
    pub fn fini_array(&self) -> Result<Option<unwind::AddressArray>, errors::FileParseError> {
        self.address_array_by_name(".fini_array")
    }

    /// Parses `.preinit_array`, if present.
    pub fn preinit_array(&self) -> Result<Option<unwind::AddressArray>, errors::FileParseError> {
        self.address_array_by_name(".preinit_array")
    }

    /// Returns true for `ET_CORE` files.
    pub fn is_core(&self) -> bool {
        matches!(self.header.elf_type.value, header::ElfType::Core)
    }

    /// Parses a Unix `ar` archive buffer.
    pub fn parse_archive(buffer: &[u8]) -> Result<Archive, errors::FileParseError> {
        Archive::parse(buffer)
    }

    fn named_blob(
        &self,
        name: &str,
    ) -> Result<Option<unwind::SectionBlob<'_>>, errors::FileParseError> {
        let Some(section_index) = self.section_index_by_name(name) else {
            return Ok(None);
        };
        Ok(Some(unwind::SectionBlob {
            section_index,
            data: self.section_data(section_index)?,
        }))
    }

    fn address_array_by_name(
        &self,
        name: &str,
    ) -> Result<Option<unwind::AddressArray>, errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;
        let Some(index) = self.section_index_by_name(name) else {
            return Ok(None);
        };
        let sh = &self.section_headers[index];
        let width = match class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        Ok(Some(unwind::AddressArray::parse(
            &self.buffer,
            sh.sh_offset() as usize,
            sh.sh_size() as usize,
            width,
            order,
        )?))
    }

    /// Parses the symbol table of the first section of type `sh_type` (`SHT_SYMTAB` / `SHT_DYNSYM`).
    ///
    /// The string table offset is resolved through the section's `sh_link`. Returns `Ok(None)` when
    /// no such section exists.
    fn parse_symbol_section(
        &self,
        sh_type: u32,
    ) -> Result<Option<symbol::SymbolTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;

        let idx = match self
            .section_headers
            .iter()
            .position(|sh| sh.sh_type() == sh_type)
        {
            Some(i) => i,
            None => return Ok(None),
        };
        let sh = &self.section_headers[idx];

        let ent_size = sh.sh_entsize() as usize;
        let sym_size = symbol::SymbolEntry::size_of(class);
        if ent_size == 0 || ent_size != sym_size {
            return Err(errors::FileParseError::InvalidFileFormat);
        }

        let offset = sh.sh_offset() as usize;
        let count = sh.sh_size() as usize / ent_size;

        let strtab = self
            .section_headers
            .get(sh.sh_link() as usize)
            .ok_or(errors::FileParseError::InvalidFileFormat)?;
        let strtab_offset = strtab.sh_offset() as usize;

        let symbols = symbol::SymbolEntry::parse_table(&self.buffer, offset, count, class, order)?;
        Ok(Some(symbol::SymbolTable {
            offset,
            strtab_offset,
            symbols,
        }))
    }

    /// Parses the static symbol table (`.symtab`), if present.
    pub fn symbols(&self) -> Result<Option<symbol::SymbolTable>, errors::FileParseError> {
        self.parse_symbol_section(section::SHT_SYMTAB)
    }

    /// Parses the dynamic symbol table (`.dynsym`), if present.
    pub fn dynamic_symbols(&self) -> Result<Option<symbol::SymbolTable>, errors::FileParseError> {
        self.parse_symbol_section(section::SHT_DYNSYM)
    }

    /// Parses the dynamic linking table (`.dynamic`), if present.
    pub fn dynamic(&self) -> Result<Option<dynamic::DynamicTable>, errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;

        let sh = match self
            .section_headers
            .iter()
            .find(|sh| sh.sh_type() == section::SHT_DYNAMIC)
        {
            Some(sh) => sh,
            None => return Ok(None),
        };

        let offset = sh.sh_offset() as usize;
        let size = sh.sh_size() as usize;
        Ok(Some(dynamic::DynamicTable::parse(
            &self.buffer,
            offset,
            size,
            class,
            order,
        )?))
    }

    /// Parses every relocation section (`SHT_REL` / `SHT_RELA`) in file order.
    ///
    /// Each item pairs the section index with its parsed entries.
    pub fn relocations(
        &self,
    ) -> Result<Vec<(usize, Vec<relocation::RelocationEntry>)>, errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;
        let mut result = Vec::new();

        for (idx, sh) in self.section_headers.iter().enumerate() {
            let with_addend = match sh.sh_type() {
                section::SHT_RELA => true,
                section::SHT_REL => false,
                _ => continue,
            };

            let ent_size = sh.sh_entsize() as usize;
            let expected = relocation::RelocationEntry::size_of(class, with_addend);
            if ent_size == 0 || ent_size != expected {
                return Err(errors::FileParseError::InvalidFileFormat);
            }

            let offset = sh.sh_offset() as usize;
            let count = sh.sh_size() as usize / ent_size;
            let entries = relocation::RelocationEntry::parse_table(
                &self.buffer,
                offset,
                count,
                with_addend,
                class,
                order,
            )?;
            result.push((idx, entries));
        }

        Ok(result)
    }

    /// Applies a RELA relocation as `symbol_value + r_addend` to the relocation target.
    ///
    /// `r_offset` is translated as a virtual address through `PT_LOAD`; if no segment matches, it
    /// is treated as a direct file offset. The write width is the ELF pointer width.
    pub fn apply_rela_address(
        &mut self,
        relocation: &relocation::RelocationEntry,
        symbol_value: u64,
    ) -> Result<(), errors::FileParseError> {
        let addend = relocation.r_addend().ok_or_else(|| {
            errors::FileParseError::UnsupportedFeature(
                "REL entries do not carry addends".to_string(),
            )
        })?;
        let value = (symbol_value as i128)
            .checked_add(addend as i128)
            .ok_or(errors::FileParseError::ValueTooLarge)?;
        if value < 0 || value > u64::MAX as i128 {
            return Err(errors::FileParseError::ValueTooLarge);
        }
        let file_offset = self
            .va_to_file_offset(relocation.r_offset())
            .unwrap_or_else(|| relocation.r_offset()) as usize;
        let order = self.byte_order()?;
        let pointer_width = match self.header.class()? {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        let write_end = file_offset
            .checked_add(pointer_width)
            .ok_or(errors::FileParseError::BufferOverflow)?;
        if write_end > self.buffer.len() {
            return Err(errors::FileParseError::BufferOverflow);
        }
        match self.header.class()? {
            ElfClass::Elf32 => {
                if value > u32::MAX as i128 {
                    return Err(errors::FileParseError::ValueTooLarge);
                }
                order.write_u32(&mut self.buffer, file_offset, value as u32);
            }
            ElfClass::Elf64 => order.write_u64(&mut self.buffer, file_offset, value as u64),
        }
        Ok(())
    }

    /// Splits a `PT_LOAD` segment at a file offset and appends a second `PT_LOAD` header.
    pub fn split_load_segment(
        &mut self,
        index: usize,
        split_file_offset: u64,
    ) -> Result<(), errors::FileParseError> {
        let ph = self
            .program_headers
            .get(index)
            .ok_or(errors::FileParseError::BufferOverflow)?;
        if ph.p_type() != PT_LOAD
            || split_file_offset <= ph.p_offset()
            || split_file_offset >= ph.p_offset() + ph.p_filesz()
        {
            return Err(errors::FileParseError::InvalidFileFormat);
        }

        let first_size = split_file_offset - ph.p_offset();
        let second_size = ph.p_filesz() - first_size;
        let spec = ProgramHeaderSpec {
            p_type: PT_LOAD,
            flags: ph.p_flags(),
            offset: split_file_offset,
            vaddr: ph.p_vaddr() + first_size,
            paddr: ph.p_paddr() + first_size,
            filesz: second_size,
            memsz: ph.p_memsz().saturating_sub(first_size),
            align: ph.p_align(),
        };

        let order = self.byte_order()?;
        self.program_headers[index].p_filesz_mut().update_with(
            &mut self.buffer,
            first_size,
            order,
        )?;
        self.program_headers[index].p_memsz_mut().update_with(
            &mut self.buffer,
            first_size,
            order,
        )?;
        self.append_program_header(spec)?;
        self.reparse()
    }

    /// Merges adjacent `PT_LOAD` segments and marks merged-away headers as `PT_NULL`.
    pub fn merge_adjacent_load_segments(&mut self) -> Result<usize, errors::FileParseError> {
        let order = self.byte_order()?;
        let mut merged = 0;
        let len = self.program_headers.len();
        for i in 0..len {
            if self.program_headers[i].p_type() != PT_LOAD {
                continue;
            }
            for j in i + 1..len {
                if self.program_headers[j].p_type() != PT_LOAD {
                    continue;
                }
                let i_end = self.program_headers[i].p_offset() + self.program_headers[i].p_filesz();
                if i_end == self.program_headers[j].p_offset()
                    && self.program_headers[i].p_flags() == self.program_headers[j].p_flags()
                {
                    let new_filesz =
                        self.program_headers[i].p_filesz() + self.program_headers[j].p_filesz();
                    let new_memsz =
                        self.program_headers[i].p_memsz() + self.program_headers[j].p_memsz();
                    self.program_headers[i].p_filesz_mut().update_with(
                        &mut self.buffer,
                        new_filesz,
                        order,
                    )?;
                    self.program_headers[i].p_memsz_mut().update_with(
                        &mut self.buffer,
                        new_memsz,
                        order,
                    )?;
                    self.program_headers[j].p_type_mut().update_with(
                        &mut self.buffer,
                        program::PT_NULL,
                        order,
                    )?;
                    merged += 1;
                }
            }
        }
        self.reparse()?;
        Ok(merged)
    }

    /// Returns the `PT_GNU_RELRO` segments.
    pub fn gnu_relro_segments(&self) -> Vec<&ProgramHeaderEntry> {
        self.program_headers
            .iter()
            .filter(|ph| ph.p_type() == program::PT_GNU_RELRO)
            .collect()
    }

    /// Writes [`ELF::buffer`] to `output_path`.
    pub fn write_file(&self, output_path: &str) -> std::io::Result<()> {
        let mut file = std::fs::File::create(output_path)?;
        use std::io::Write;
        file.write_all(&self.buffer)?;
        Ok(())
    }

    /// Reads and parses an ELF file from disk.
    pub fn from_file(path: &str) -> Result<Self, errors::FileParseError> {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut buffer)?;
        Self::from_buffer(buffer)
    }

    /// Parses an ELF image from an owned byte buffer.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, errors::FileParseError> {
        let header = ElfHeader::parse(&buffer)?;
        let byte_order = header.ei_data.value;
        let order = ByteOrder::from_ei_data(byte_order)?;
        let class = header.class()?;
        let program_headers = ProgramHeaderEntry::parse_program_headers(
            &buffer,
            header.ph_off.value,
            header.ph_ent_size.value,
            header.ph_num.value,
            class,
            order,
        )?;
        let section_count = Self::section_header_count(&buffer, &header, class, order)?;
        let section_headers = SectionHeaderEntry::parse_section_headers(
            &buffer,
            header.sh_off.value,
            header.sh_ent_size.value,
            section_count,
            class,
            order,
        )?;

        Ok(ELF {
            buffer,
            header,
            program_headers,
            section_headers,
        })
    }

    fn reparse(&mut self) -> Result<(), errors::FileParseError> {
        let buf = std::mem::take(&mut self.buffer);
        *self = Self::from_buffer(buf)?;
        Ok(())
    }

    fn section_header_count(
        buffer: &[u8],
        header: &ElfHeader,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<usize, errors::FileParseError> {
        if header.sh_num.value != 0 {
            return Ok(header.sh_num.value as usize);
        }
        if header.sh_off.value == 0 || header.sh_ent_size.value == 0 {
            return Ok(0);
        }
        let base = header.sh_off.value as usize;
        match class {
            ElfClass::Elf32 => Ok(order.read_u32(buffer, base + 20)? as usize),
            ElfClass::Elf64 => Ok(order.read_u64(buffer, base + 32)? as usize),
        }
    }

    fn min_file_offset(&self) -> u64 {
        let mut min = u64::MAX;
        for ph in &self.program_headers {
            let off = ph.p_offset();
            if off > 0 {
                min = min.min(off);
            }
        }
        if self.header.sh_off.value > 0 {
            min = min.min(self.header.sh_off.value);
        }
        if min == u64::MAX {
            self.buffer.len() as u64
        } else {
            min
        }
    }

    /// Inserts a new section, creating `.shstrtab` when the file does not have one.
    pub fn insert_section(&mut self, new: NewSection) -> Result<(), errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;
        let ent_size = self.section_header_size(class)?;
        self.ensure_section_table(class, order, ent_size)?;

        let strndx = if self.header.sh_strndx.value as usize >= self.section_headers.len()
            || self.header.sh_strndx.value == 0
        {
            self.create_shstrtab(class, order, ent_size)?
        } else {
            self.header.sh_strndx.value as usize
        };

        let name_off = self.append_section_name(strndx, &new.name, class, order, ent_size)?;
        let (sh_base, data_offset) = match new.offset {
            Some(offset) => {
                self.insert_bytes_at(offset as usize, &new.data, true)?;
                let sh_base = self.append_section_header_space(ent_size)?;
                let data_offset = if sh_base <= offset as usize {
                    offset + ent_size as u64
                } else {
                    offset
                };
                (sh_base, data_offset)
            }
            None => {
                let sh_base = self.append_section_header_space(ent_size)?;
                let offset = self.buffer.len() as u64;
                self.buffer.extend_from_slice(&new.data);
                (sh_base, offset)
            }
        };

        self.write_section_header(
            sh_base,
            SectionHeaderSpec {
                name: name_off,
                sh_type: new.sh_type,
                flags: new.flags,
                addr: new.addr.unwrap_or(0),
                offset: data_offset,
                size: new.data.len() as u64,
                link: new.link.unwrap_or(0),
                info: new.info.unwrap_or(0),
                addralign: new.addralign.unwrap_or(1),
                entsize: new.entsize.unwrap_or(0),
            },
            class,
            order,
        )?;
        self.write_section_count(self.section_headers.len() + 1, class, order)?;
        self.reparse()
    }

    /// Appends a new `PT_LOAD` program header and segment data.
    pub fn insert_pt_load(&mut self, new: NewPtLoad) -> Result<(), errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;
        let ph_ent_size = self.header.ph_ent_size.value as usize;
        if ph_ent_size == 0 {
            return Err(errors::FileParseError::InvalidFileFormat);
        }

        let ph_off = self.header.ph_off.value as usize;
        let table_end = ph_off + self.program_headers.len() * ph_ent_size;
        let min_off = self.min_file_offset() as usize;

        if table_end + ph_ent_size > min_off {
            self.buffer
                .splice(table_end..table_end, std::iter::repeat_n(0u8, ph_ent_size));
            self.bump_offsets_from(table_end, ph_ent_size as i64)?;
        }

        let ph_base = table_end;
        let data_offset = self.buffer.len() as u64;
        self.buffer.extend_from_slice(&new.data);

        let (vaddr, align) = self.resolve_pt_load_layout(&new)?;

        match class {
            ElfClass::Elf32 => {
                order.write_u32(&mut self.buffer, ph_base, PT_LOAD);
                order.write_u32(&mut self.buffer, ph_base + 4, data_offset as u32);
                order.write_u32(&mut self.buffer, ph_base + 8, vaddr as u32);
                order.write_u32(&mut self.buffer, ph_base + 12, vaddr as u32);
                order.write_u32(&mut self.buffer, ph_base + 16, new.data.len() as u32);
                order.write_u32(&mut self.buffer, ph_base + 20, new.data.len() as u32);
                order.write_u32(&mut self.buffer, ph_base + 24, new.flags);
                order.write_u32(&mut self.buffer, ph_base + 28, align as u32);
            }
            ElfClass::Elf64 => {
                order.write_u32(&mut self.buffer, ph_base, PT_LOAD);
                order.write_u32(&mut self.buffer, ph_base + 4, new.flags);
                order.write_u64(&mut self.buffer, ph_base + 8, data_offset);
                order.write_u64(&mut self.buffer, ph_base + 16, vaddr);
                order.write_u64(&mut self.buffer, ph_base + 24, vaddr);
                order.write_u64(&mut self.buffer, ph_base + 32, new.data.len() as u64);
                order.write_u64(&mut self.buffer, ph_base + 40, new.data.len() as u64);
                order.write_u64(&mut self.buffer, ph_base + 48, align);
            }
        }

        let new_phnum = self.header.ph_num.value + 1;
        match class {
            ElfClass::Elf32 => order.write_u16(&mut self.buffer, 44, new_phnum),
            ElfClass::Elf64 => order.write_u16(&mut self.buffer, 56, new_phnum),
        }

        self.reparse()
    }

    fn append_program_header(
        &mut self,
        spec: ProgramHeaderSpec,
    ) -> Result<(), errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;
        let ph_ent_size = self.header.ph_ent_size.value as usize;
        if ph_ent_size == 0 {
            return Err(errors::FileParseError::InvalidFileFormat);
        }

        let ph_off = self.header.ph_off.value as usize;
        let table_end = ph_off + self.program_headers.len() * ph_ent_size;
        let min_off = self.min_file_offset() as usize;
        if table_end + ph_ent_size > min_off {
            self.buffer
                .splice(table_end..table_end, std::iter::repeat_n(0u8, ph_ent_size));
            self.bump_offsets_from(table_end, ph_ent_size as i64)?;
        }

        self.write_program_header(table_end, spec, class, order);
        let new_phnum = self.header.ph_num.value + 1;
        match class {
            ElfClass::Elf32 => order.write_u16(&mut self.buffer, 44, new_phnum),
            ElfClass::Elf64 => order.write_u16(&mut self.buffer, 56, new_phnum),
        }
        Ok(())
    }

    fn write_program_header(
        &mut self,
        ph_base: usize,
        spec: ProgramHeaderSpec,
        class: ElfClass,
        order: ByteOrder,
    ) {
        match class {
            ElfClass::Elf32 => {
                order.write_u32(&mut self.buffer, ph_base, spec.p_type);
                order.write_u32(&mut self.buffer, ph_base + 4, spec.offset as u32);
                order.write_u32(&mut self.buffer, ph_base + 8, spec.vaddr as u32);
                order.write_u32(&mut self.buffer, ph_base + 12, spec.paddr as u32);
                order.write_u32(&mut self.buffer, ph_base + 16, spec.filesz as u32);
                order.write_u32(&mut self.buffer, ph_base + 20, spec.memsz as u32);
                order.write_u32(&mut self.buffer, ph_base + 24, spec.flags);
                order.write_u32(&mut self.buffer, ph_base + 28, spec.align as u32);
            }
            ElfClass::Elf64 => {
                order.write_u32(&mut self.buffer, ph_base, spec.p_type);
                order.write_u32(&mut self.buffer, ph_base + 4, spec.flags);
                order.write_u64(&mut self.buffer, ph_base + 8, spec.offset);
                order.write_u64(&mut self.buffer, ph_base + 16, spec.vaddr);
                order.write_u64(&mut self.buffer, ph_base + 24, spec.paddr);
                order.write_u64(&mut self.buffer, ph_base + 32, spec.filesz);
                order.write_u64(&mut self.buffer, ph_base + 40, spec.memsz);
                order.write_u64(&mut self.buffer, ph_base + 48, spec.align);
            }
        }
    }

    fn resolve_pt_load_layout(
        &self,
        new: &NewPtLoad,
    ) -> Result<(u64, u64), errors::FileParseError> {
        let align = new.align.unwrap_or_else(|| {
            self.program_headers
                .iter()
                .filter(|ph| ph.p_type() == PT_LOAD)
                .map(|ph| ph.p_align())
                .next_back()
                .unwrap_or(0x1000)
        });

        let vaddr = match new.vaddr {
            Some(v) => v,
            None => {
                let last = self
                    .program_headers
                    .iter()
                    .filter(|ph| ph.p_type() == PT_LOAD)
                    .next_back();
                match last {
                    Some(ph) => {
                        let end = ph.p_vaddr() + ph.p_memsz();
                        (end + align - 1) & !(align - 1)
                    }
                    None => 0,
                }
            }
        };

        Ok((vaddr, align))
    }

    fn section_header_size(&self, class: ElfClass) -> Result<usize, errors::FileParseError> {
        if self.header.sh_ent_size.value != 0 {
            return Ok(self.header.sh_ent_size.value as usize);
        }
        Ok(match class {
            ElfClass::Elf32 => 40,
            ElfClass::Elf64 => 64,
        })
    }

    fn ensure_section_table(
        &mut self,
        class: ElfClass,
        order: ByteOrder,
        ent_size: usize,
    ) -> Result<(), errors::FileParseError> {
        if self.header.sh_ent_size.value == 0 {
            let off = match class {
                ElfClass::Elf32 => 46,
                ElfClass::Elf64 => 58,
            };
            order.write_u16(&mut self.buffer, off, ent_size as u16);
            self.header.sh_ent_size.value = ent_size as u16;
        }
        if self.header.sh_off.value == 0 {
            let sh_off = self.buffer.len() as u64;
            self.buffer.resize(self.buffer.len() + ent_size, 0);
            self.write_header_shoff(sh_off, class, order);
            self.write_section_count(1, class, order)?;
            self.reparse()?;
        }
        Ok(())
    }

    fn create_shstrtab(
        &mut self,
        class: ElfClass,
        order: ByteOrder,
        ent_size: usize,
    ) -> Result<usize, errors::FileParseError> {
        let section_index = self.section_headers.len();
        let data = b"\0.shstrtab\0";
        let sh_base = self.append_section_header_space(ent_size)?;
        let data_offset = self.buffer.len() as u64;
        self.buffer.extend_from_slice(data);
        self.write_section_header(
            sh_base,
            SectionHeaderSpec {
                name: 1,
                sh_type: section::SHT_STRTAB,
                flags: 0,
                addr: 0,
                offset: data_offset,
                size: data.len() as u64,
                link: 0,
                info: 0,
                addralign: 1,
                entsize: 0,
            },
            class,
            order,
        )?;
        self.write_header_shstrndx(section_index as u16, class, order);
        self.write_section_count(section_index + 1, class, order)?;
        self.reparse()?;
        Ok(section_index)
    }

    fn append_section_name(
        &mut self,
        strndx: usize,
        name: &str,
        class: ElfClass,
        order: ByteOrder,
        ent_size: usize,
    ) -> Result<u32, errors::FileParseError> {
        let strtab_off = self.section_headers[strndx].sh_offset() as usize;
        let strtab_size = self.section_headers[strndx].sh_size() as usize;
        let name_off = strtab_size as u32;
        let mut name_bytes = name.as_bytes().to_vec();
        name_bytes.push(0);
        let strtab_end = strtab_off + strtab_size;
        if self.buffer.len() < strtab_end {
            self.buffer.resize(strtab_end, 0);
        }
        self.insert_bytes_at(strtab_end, &name_bytes, true)?;
        let strtab_sh_base = self.header.sh_off.value as usize + strndx * ent_size;
        let new_size = (strtab_size + name_bytes.len()) as u64;
        match class {
            ElfClass::Elf32 => {
                order.write_u32(&mut self.buffer, strtab_sh_base + 20, new_size as u32)
            }
            ElfClass::Elf64 => order.write_u64(&mut self.buffer, strtab_sh_base + 32, new_size),
        }
        Ok(name_off)
    }

    fn append_section_header_space(
        &mut self,
        ent_size: usize,
    ) -> Result<usize, errors::FileParseError> {
        let sh_table_end =
            self.header.sh_off.value as usize + self.section_headers.len() * ent_size;
        if self.buffer.len() < sh_table_end {
            self.buffer.resize(sh_table_end, 0);
        }
        self.buffer.splice(
            sh_table_end..sh_table_end,
            std::iter::repeat_n(0u8, ent_size),
        );
        self.bump_offsets_from(sh_table_end, ent_size as i64)?;
        Ok(sh_table_end)
    }

    fn write_section_header(
        &mut self,
        sh_base: usize,
        spec: SectionHeaderSpec,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<(), errors::FileParseError> {
        match class {
            ElfClass::Elf32 => {
                order.write_u32(&mut self.buffer, sh_base, spec.name);
                order.write_u32(&mut self.buffer, sh_base + 4, spec.sh_type);
                order.write_u32(&mut self.buffer, sh_base + 8, spec.flags as u32);
                order.write_u32(&mut self.buffer, sh_base + 12, spec.addr as u32);
                order.write_u32(&mut self.buffer, sh_base + 16, spec.offset as u32);
                order.write_u32(&mut self.buffer, sh_base + 20, spec.size as u32);
                order.write_u32(&mut self.buffer, sh_base + 24, spec.link);
                order.write_u32(&mut self.buffer, sh_base + 28, spec.info);
                order.write_u32(&mut self.buffer, sh_base + 32, spec.addralign as u32);
                order.write_u32(&mut self.buffer, sh_base + 36, spec.entsize as u32);
            }
            ElfClass::Elf64 => {
                order.write_u32(&mut self.buffer, sh_base, spec.name);
                order.write_u32(&mut self.buffer, sh_base + 4, spec.sh_type);
                order.write_u64(&mut self.buffer, sh_base + 8, spec.flags);
                order.write_u64(&mut self.buffer, sh_base + 16, spec.addr);
                order.write_u64(&mut self.buffer, sh_base + 24, spec.offset);
                order.write_u64(&mut self.buffer, sh_base + 32, spec.size);
                order.write_u32(&mut self.buffer, sh_base + 40, spec.link);
                order.write_u32(&mut self.buffer, sh_base + 44, spec.info);
                order.write_u64(&mut self.buffer, sh_base + 48, spec.addralign);
                order.write_u64(&mut self.buffer, sh_base + 56, spec.entsize);
            }
        }
        Ok(())
    }

    fn insert_bytes_at(
        &mut self,
        at: usize,
        bytes: &[u8],
        sync_load: bool,
    ) -> Result<(), errors::FileParseError> {
        if at > self.buffer.len() {
            return Err(errors::FileParseError::BufferOverflow);
        }
        let moves_tables = at <= self.header.sh_off.value as usize
            || (self.header.ph_off.value != 0 && at <= self.header.ph_off.value as usize);
        if sync_load {
            self.sync_pt_load_insert(at as u64, bytes.len() as u64)?;
        }
        self.bump_offsets_from(at, bytes.len() as i64)?;
        self.buffer.splice(at..at, bytes.iter().copied());
        if moves_tables {
            self.reparse()?;
        }
        Ok(())
    }

    fn sync_pt_load_insert(&mut self, at: u64, len: u64) -> Result<(), errors::FileParseError> {
        let order = self.byte_order()?;
        for ph in &mut self.program_headers {
            if ph.p_type() != PT_LOAD {
                continue;
            }
            let start = ph.p_offset();
            let end = start + ph.p_filesz();
            if at >= start && at <= end {
                let new_filesz = ph.p_filesz() + len;
                let new_memsz = ph.p_memsz() + len;
                ph.p_filesz_mut()
                    .update_with(&mut self.buffer, new_filesz, order)?;
                ph.p_memsz_mut()
                    .update_with(&mut self.buffer, new_memsz, order)?;
            }
        }
        Ok(())
    }

    fn write_header_shoff(&mut self, value: u64, class: ElfClass, order: ByteOrder) {
        self.header.sh_off.value = value;
        match class {
            ElfClass::Elf32 => order.write_u32(&mut self.buffer, 32, value as u32),
            ElfClass::Elf64 => order.write_u64(&mut self.buffer, 40, value),
        }
    }

    fn write_header_shstrndx(&mut self, value: u16, class: ElfClass, order: ByteOrder) {
        self.header.sh_strndx.value = value;
        match class {
            ElfClass::Elf32 => order.write_u16(&mut self.buffer, 50, value),
            ElfClass::Elf64 => order.write_u16(&mut self.buffer, 62, value),
        }
    }

    fn write_section_count(
        &mut self,
        count: usize,
        class: ElfClass,
        order: ByteOrder,
    ) -> Result<(), errors::FileParseError> {
        if count <= u16::MAX as usize && self.header.sh_num.value != 0 {
            let value = count as u16;
            self.header.sh_num.value = value;
            match class {
                ElfClass::Elf32 => order.write_u16(&mut self.buffer, 48, value),
                ElfClass::Elf64 => order.write_u16(&mut self.buffer, 60, value),
            }
            return Ok(());
        }

        match class {
            ElfClass::Elf32 => {
                order.write_u16(&mut self.buffer, 48, 0);
                order.write_u32(
                    &mut self.buffer,
                    self.header.sh_off.value as usize + 20,
                    count as u32,
                );
            }
            ElfClass::Elf64 => {
                order.write_u16(&mut self.buffer, 60, 0);
                order.write_u64(
                    &mut self.buffer,
                    self.header.sh_off.value as usize + 32,
                    count as u64,
                );
            }
        }
        self.header.sh_num.value = 0;
        Ok(())
    }

    fn bump_offsets_from(&mut self, at: usize, delta: i64) -> Result<(), errors::FileParseError> {
        if delta == 0 {
            return Ok(());
        }
        let delta_u = delta as u64;
        let order = self.byte_order()?;
        let class = self.header.class()?;

        if self.header.ph_off.value as usize >= at {
            self.header.ph_off.value += delta_u;
            match class {
                ElfClass::Elf32 => {
                    order.write_u32(&mut self.buffer, 28, self.header.ph_off.value as u32)
                }
                ElfClass::Elf64 => order.write_u64(&mut self.buffer, 32, self.header.ph_off.value),
            }
        }

        if self.header.sh_off.value as usize >= at {
            self.header.sh_off.value += delta_u;
            let off = match class {
                ElfClass::Elf32 => 32,
                ElfClass::Elf64 => 40,
            };
            match class {
                ElfClass::Elf32 => {
                    order.write_u32(&mut self.buffer, off, self.header.sh_off.value as u32)
                }
                ElfClass::Elf64 => order.write_u64(&mut self.buffer, off, self.header.sh_off.value),
            }
        }

        for ph in &mut self.program_headers {
            if ph.p_offset() as usize >= at {
                let new_off = ph.p_offset() + delta_u;
                ph.p_offset_mut()
                    .update_with(&mut self.buffer, new_off, order)?;
            }
        }

        for sh in &mut self.section_headers {
            if sh.sh_offset() as usize >= at {
                let new_off = sh.sh_offset() + delta_u;
                sh.sh_offset_mut()
                    .update_with(&mut self.buffer, new_off, order)?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SectionHeaderSpec {
    name: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
}

#[derive(Clone, Copy)]
struct ProgramHeaderSpec {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}
