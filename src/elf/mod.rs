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

pub mod dynamic;
pub mod header;
pub mod program;
pub mod relocation;
pub mod section;
pub mod symbol;

use crate::errors;
use crate::field::ByteOrder;
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
        let section_headers = SectionHeaderEntry::parse_section_headers(
            &buffer,
            header.sh_off.value,
            header.sh_ent_size.value,
            header.sh_num.value,
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

    /// Appends a new section (requires an existing `.shstrtab`).
    pub fn insert_section(&mut self, new: NewSection) -> Result<(), errors::FileParseError> {
        let order = self.byte_order()?;
        let class = self.header.class()?;
        let strndx = self.header.sh_strndx.value as usize;
        if strndx >= self.section_headers.len() {
            return Err(errors::FileParseError::InvalidFileFormat);
        }

        let strtab_off = self.section_headers[strndx].sh_offset() as usize;
        let strtab_size = self.section_headers[strndx].sh_size() as usize;
        let name_off = strtab_size as u32;
        let name_len = new.name.len() + 1;

        let mut name_bytes = new.name.into_bytes();
        name_bytes.push(0);
        let strtab_end = strtab_off + strtab_size;
        if self.buffer.len() < strtab_end {
            self.buffer.resize(strtab_end, 0);
        }
        self.buffer
            .splice(strtab_end..strtab_end, name_bytes.iter().copied());

        let data_offset = self.buffer.len() as u64;
        self.buffer.extend_from_slice(&new.data);

        let ent_size = self.header.sh_ent_size.value as usize;
        let sh_table_end =
            self.header.sh_off.value as usize + self.section_headers.len() * ent_size;
        if self.buffer.len() < sh_table_end + ent_size {
            self.buffer.resize(sh_table_end + ent_size, 0);
        }

        let sh_base = sh_table_end;
        match class {
            ElfClass::Elf32 => {
                order.write_u32(&mut self.buffer, sh_base, name_off);
                order.write_u32(&mut self.buffer, sh_base + 4, new.sh_type);
                order.write_u32(&mut self.buffer, sh_base + 8, new.flags as u32);
                order.write_u32(&mut self.buffer, sh_base + 12, 0);
                order.write_u32(&mut self.buffer, sh_base + 16, data_offset as u32);
                order.write_u32(&mut self.buffer, sh_base + 20, new.data.len() as u32);
                order.write_u32(&mut self.buffer, sh_base + 24, 0);
                order.write_u32(&mut self.buffer, sh_base + 28, 0);
                order.write_u32(&mut self.buffer, sh_base + 32, 1);
                order.write_u32(&mut self.buffer, sh_base + 36, 0);
            }
            ElfClass::Elf64 => {
                order.write_u32(&mut self.buffer, sh_base, name_off);
                order.write_u32(&mut self.buffer, sh_base + 4, new.sh_type);
                order.write_u64(&mut self.buffer, sh_base + 8, new.flags);
                order.write_u64(&mut self.buffer, sh_base + 16, 0);
                order.write_u64(&mut self.buffer, sh_base + 24, data_offset);
                order.write_u64(&mut self.buffer, sh_base + 32, new.data.len() as u64);
                order.write_u32(&mut self.buffer, sh_base + 40, 0);
                order.write_u32(&mut self.buffer, sh_base + 44, 0);
                order.write_u64(&mut self.buffer, sh_base + 48, 1);
                order.write_u64(&mut self.buffer, sh_base + 56, 0);
            }
        }

        let new_strtab_size = (strtab_size + name_len) as u64;
        let strtab_sh_base = self.header.sh_off.value as usize + strndx * ent_size;
        match class {
            ElfClass::Elf32 => order.write_u32(
                &mut self.buffer,
                strtab_sh_base + 20,
                new_strtab_size as u32,
            ),
            ElfClass::Elf64 => {
                order.write_u64(&mut self.buffer, strtab_sh_base + 32, new_strtab_size)
            }
        }

        let new_shnum = self.header.sh_num.value + 1;
        match class {
            ElfClass::Elf32 => {
                order.write_u16(&mut self.buffer, 48, new_shnum);
            }
            ElfClass::Elf64 => {
                order.write_u16(&mut self.buffer, 60, new_shnum);
            }
        }

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
