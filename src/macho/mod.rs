//! Facilities for reading and modifying Mach-O binaries.
//!
//! FAT wrappers are unpacked automatically; [`MachO`] always refers to a thin Mach-O image.
//! Byte order is derived from the magic bytes at file offset 0 — there is no endianness field in
//! the header.

pub mod bitcode;
pub mod dyld;
pub mod fat;
pub mod header;
pub mod load_command;
pub mod relocation;
pub mod section;
pub mod segment;
pub mod symbol;

use crate::errors;
use crate::field::ByteOrder;
use header::MachHeader;
use load_command::{
    DyldInfoCommand, LoadCommand, TypedCommand, LC_CODE_SIGNATURE, LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_SEGMENT, LC_SEGMENT_64,
};
use section::{NewSection, SectionEntry};
use segment::{NewSegment, SegmentEntry};
use symbol::SymbolTable;

/// A parsed Mach-O image backed by an owned byte buffer.
pub struct MachO {
    /// Full file contents (thin Mach-O after FAT unpacking).
    pub buffer: Vec<u8>,
    /// Mach-O header (`mach_header` / `mach_header_64`).
    pub header: MachHeader,
    /// Load command headers (`cmd` + `cmdsize` only).
    pub load_commands: Vec<LoadCommand>,
    /// Parsed `LC_SEGMENT` / `LC_SEGMENT_64` commands.
    pub segments: Vec<SegmentEntry>,
    /// Parsed `section` / `section_64` records nested inside segments.
    pub sections: Vec<SectionEntry>,
}

impl MachO {
    /// Byte order derived from the Mach-O header magic bytes on disk (no endianness byte exists).
    pub fn byte_order(&self) -> ByteOrder {
        let bytes: [u8; 4] = self.buffer[0..4].try_into().unwrap_or([0, 0, 0, 0]);
        ByteOrder::from_macho_header_bytes(bytes).unwrap_or(ByteOrder::Little)
    }

    /// Writes [`MachO::buffer`] to `output_path`.
    pub fn write_file(&self, output_path: &str) -> std::io::Result<()> {
        let mut file = std::fs::File::create(output_path)?;
        use std::io::Write;
        file.write_all(&self.buffer)?;
        Ok(())
    }

    /// Reads and parses a Mach-O file from disk (FAT binaries are unpacked).
    pub fn from_file(path: &str) -> Result<Self, errors::FileParseError> {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut buffer)?;
        Self::from_buffer(buffer)
    }

    /// Lists the architecture slices of a FAT binary at `path`.
    ///
    /// Returns an empty vector for thin (non-FAT) Mach-O files.
    pub fn fat_architectures(path: &str) -> Result<Vec<fat::FatArch>, errors::FileParseError> {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut buffer)?;
        Ok(fat::FatHeader::parse(&buffer)?
            .map(|f| f.arches)
            .unwrap_or_default())
    }

    /// Parses the FAT slice at `index`, or the whole file when it is a thin Mach-O and `index` is 0.
    pub fn from_fat_index(path: &str, index: usize) -> Result<Self, errors::FileParseError> {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut buffer)?;
        Self::from_fat_index_buffer(buffer, index)
    }

    /// Parses the FAT slice at `index` from an owned buffer (see [`MachO::from_fat_index`]).
    ///
    /// Only the selected architecture slice is copied into the returned [`MachO`]; other FAT slices
    /// are not included in the owned buffer.
    pub fn from_fat_index_buffer(
        buffer: Vec<u8>,
        index: usize,
    ) -> Result<Self, errors::FileParseError> {
        if let Some(fat) = fat::FatHeader::parse(&buffer)? {
            let arch = fat
                .arches
                .get(index)
                .ok_or(errors::FileParseError::BufferOverflow)?;
            let inner = fat.slice_bytes(&buffer, arch)?;
            return Self::from_buffer(inner);
        }
        if index != 0 {
            return Err(errors::FileParseError::BufferOverflow);
        }
        Self::from_buffer(buffer)
    }

    /// Reads only the thin Mach-O slice at `index` from a FAT file on disk (no full-file copy).
    pub fn from_fat_index_read(path: &str, index: usize) -> Result<Self, errors::FileParseError> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(path)?;
        let mut header_buf = [0u8; 8];
        file.read_exact(&mut header_buf)?;
        let magic_be = u32::from_be_bytes(header_buf[0..4].try_into().unwrap());
        if magic_be != 0xCAFE_BABE && magic_be != 0xCAFEBABF {
            if index != 0 {
                return Err(errors::FileParseError::BufferOverflow);
            }
            let mut buffer = header_buf.to_vec();
            file.read_to_end(&mut buffer)?;
            return Self::from_buffer(buffer);
        }

        let fat = {
            let mut buf = header_buf.to_vec();
            file.read_to_end(&mut buf)?;
            fat::FatHeader::parse(&buf)?.ok_or(errors::FileParseError::InvalidFileFormat)?
        };
        let arch = fat
            .arches
            .get(index)
            .ok_or(errors::FileParseError::BufferOverflow)?;
        let (start, end) = arch.byte_range()?;
        file.seek(SeekFrom::Start(start as u64))?;
        let mut inner = vec![0u8; end - start];
        file.read_exact(&mut inner)?;
        Self::from_buffer(inner)
    }

    /// Returns a borrowed view of one FAT slice inside `buffer` without copying.
    pub fn fat_slice_ref<'a>(
        buffer: &'a [u8],
        index: usize,
    ) -> Result<&'a [u8], errors::FileParseError> {
        let fat =
            fat::FatHeader::parse(buffer)?.ok_or(errors::FileParseError::InvalidFileFormat)?;
        let arch = fat
            .arches
            .get(index)
            .ok_or(errors::FileParseError::BufferOverflow)?;
        fat.slice_ref(buffer, arch)
    }

    /// Parses a Mach-O image from an owned byte buffer.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 4 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let magic_bytes: [u8; 4] = buffer
            .get(0..4)
            .ok_or(errors::FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| errors::FileParseError::BufferOverflow)?;

        let magic_le = u32::from_le_bytes(magic_bytes);

        if let Some(fat) = fat::FatHeader::parse(&buffer)? {
            let arch = fat
                .arches
                .first()
                .ok_or(errors::FileParseError::InvalidFileFormat)?;
            let inner = fat.slice_bytes(&buffer, arch)?;
            return MachO::from_buffer(inner);
        }

        let (header_size, byte_order, is_64bit) = match magic_le {
            0xFEEDFACE => (28, ByteOrder::Little, false),
            0xFEEDFACF => (32, ByteOrder::Little, true),
            0xCEFAEDFE => (28, ByteOrder::Big, false),
            0xCFFAEDFE => (32, ByteOrder::Big, true),
            _ => return Err(errors::FileParseError::InvalidFileFormat),
        };

        if buffer.len() < header_size {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let header = MachHeader::parse(&buffer, byte_order, is_64bit)?;
        let load_commands_offset = header_size;

        if buffer.len() < load_commands_offset + header.sizeofcmds.value as usize {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let load_commands = LoadCommand::parse_load_commands(
            &buffer,
            load_commands_offset,
            header.ncmds.value,
            byte_order,
        )?;
        let segments = SegmentEntry::parse_segments(&buffer, &load_commands, byte_order)?;
        let sections = SectionEntry::parse_sections(&buffer, &load_commands, byte_order)?;

        Ok(MachO {
            buffer,
            header,
            load_commands,
            segments,
            sections,
        })
    }

    /// Iterates the typed payloads of the load commands HexSpell models.
    ///
    /// Commands without a typed view (segments, thread state, version) are skipped.
    pub fn typed_commands(&self) -> Result<Vec<TypedCommand>, errors::FileParseError> {
        let order = self.byte_order();
        let mut out = Vec::new();
        for cmd in &self.load_commands {
            if let Some(typed) = cmd.typed(&self.buffer, order)? {
                out.push(typed);
            }
        }
        Ok(out)
    }

    /// Parses the symbol table referenced by `LC_SYMTAB`, if present.
    ///
    /// Returns `Ok(None)` when the image has no symbol table command.
    pub fn symbols(&self) -> Result<Option<SymbolTable>, errors::FileParseError> {
        let order = self.byte_order();
        let is_64 = self.is_64bit();
        for cmd in &self.load_commands {
            if let Some(TypedCommand::Symtab(symtab)) = cmd.typed(&self.buffer, order)? {
                return Ok(Some(SymbolTable::parse(
                    &self.buffer,
                    &symtab,
                    is_64,
                    order,
                )?));
            }
        }
        Ok(None)
    }

    /// Returns the paths of the dynamic libraries the image links against (`LC_LOAD_DYLIB` and
    /// its weak / re-export / lazy variants). The dylib's own `LC_ID_DYLIB` is not included.
    pub fn linked_dylibs(&self) -> Result<Vec<String>, errors::FileParseError> {
        use load_command::{
            LC_LAZY_LOAD_DYLIB, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
        };
        let order = self.byte_order();
        let mut out = Vec::new();
        for cmd in &self.load_commands {
            if matches!(
                cmd.cmd.value,
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            ) {
                if let Some(TypedCommand::Dylib(dylib)) = cmd.typed(&self.buffer, order)? {
                    out.push(dylib.name);
                }
            }
        }
        Ok(out)
    }

    /// Parses relocation entries for every section that has `nreloc > 0`.
    pub fn relocations(
        &self,
    ) -> Result<Vec<(usize, Vec<relocation::RelocationEntry>)>, errors::FileParseError> {
        let order = self.byte_order();
        let mut out = Vec::new();
        for (i, section) in self.sections.iter().enumerate() {
            if section.nreloc() > 0 {
                out.push((i, section.relocations(&self.buffer, order)?));
            }
        }
        Ok(out)
    }

    /// Decodes exported symbols from `LC_DYLD_EXPORTS_TRIE` or the export blob in `LC_DYLD_INFO`.
    pub fn exports(&self) -> Result<Vec<dyld::ExportTrieEntry>, errors::FileParseError> {
        let order = self.byte_order();
        if let Some(blob) = self.export_trie_blob()? {
            return dyld::decode_export_trie(blob);
        }
        for cmd in &self.load_commands {
            if let Some(TypedCommand::DyldInfo(info)) = cmd.typed(&self.buffer, order)? {
                if info.export_size.value > 0 {
                    let off = info.export_off.value as usize;
                    let size = info.export_size.value as usize;
                    let blob = self
                        .buffer
                        .get(off..off + size)
                        .ok_or(errors::FileParseError::BufferOverflow)?;
                    return dyld::decode_export_trie(blob);
                }
            }
        }
        Ok(Vec::new())
    }

    /// Decodes bind opcodes from `LC_DYLD_INFO` (non-lazy, lazy, or weak).
    pub fn bind_opcodes(
        &self,
        lazy: bool,
        weak: bool,
    ) -> Result<Vec<dyld::BindOpcode>, errors::FileParseError> {
        let order = self.byte_order();
        for cmd in &self.load_commands {
            if let Some(TypedCommand::DyldInfo(info)) = cmd.typed(&self.buffer, order)? {
                let (off, size) = if weak {
                    (info.weak_bind_off.value, info.weak_bind_size.value)
                } else if lazy {
                    (info.lazy_bind_off.value, info.lazy_bind_size.value)
                } else {
                    (info.bind_off.value, info.bind_size.value)
                };
                if size > 0 {
                    let start = off as usize;
                    let end = start + size as usize;
                    let blob = self
                        .buffer
                        .get(start..end)
                        .ok_or(errors::FileParseError::BufferOverflow)?;
                    return dyld::decode_bind_opcodes(blob);
                }
            }
        }
        Ok(Vec::new())
    }

    /// Returns sections nested under the `__LLVM` bitcode segment, if present.
    pub fn llvm_sections(&self) -> Vec<&SectionEntry> {
        bitcode::llvm_sections(&self.segments, &self.sections)
    }

    /// Inserts raw load-command bytes at `index` (0 = first command after the Mach-O header).
    pub fn insert_load_command_at(
        &mut self,
        index: usize,
        cmd_bytes: &[u8],
    ) -> Result<(), errors::FileParseError> {
        if cmd_bytes.len() < 8 || cmd_bytes.len() % 8 != 0 {
            return Err(errors::FileParseError::InvalidFileFormat);
        }
        let at = self.load_command_offset(index)?;
        self.splice_load_region(at, 0, cmd_bytes)?;
        let order = self.byte_order();
        let new_ncmds = self.header.ncmds.value + 1;
        let new_size = self.header.sizeofcmds.value + cmd_bytes.len() as u32;
        order.write_u32(&mut self.buffer, 16, new_ncmds);
        order.write_u32(&mut self.buffer, 20, new_size);
        self.bump_fileoffs_after_splice(at, cmd_bytes.len() as i64)?;
        self.preserve_code_signature_alignment()?;
        self.reparse()
    }

    /// Removes the load command at `index`.
    pub fn remove_load_command(&mut self, index: usize) -> Result<(), errors::FileParseError> {
        let at = self.load_command_offset(index)?;
        let remove_len = self.load_commands[index].cmdsize.value as usize;
        let delta = -(remove_len as i64);
        self.splice_load_region(at, remove_len, &[])?;
        let order = self.byte_order();
        let new_ncmds = self.header.ncmds.value - 1;
        let new_size = self.header.sizeofcmds.value - remove_len as u32;
        order.write_u32(&mut self.buffer, 16, new_ncmds);
        order.write_u32(&mut self.buffer, 20, new_size);
        self.bump_fileoffs_after_splice(at, delta)?;
        self.preserve_code_signature_alignment()?;
        self.reparse()
    }

    /// Adds a `section_64` / `section` record inside an existing segment.
    pub fn add_section(
        &mut self,
        segment_index: usize,
        new: NewSection,
    ) -> Result<(), errors::FileParseError> {
        if segment_index >= self.segments.len() {
            return Err(errors::FileParseError::BufferOverflow);
        }
        let is_64 = self.is_64bit();
        let record_size = if is_64 { 80 } else { 68 };
        let seg_hdr_size = if is_64 { 72 } else { 56 };
        let lc_idx = self.segment_lc_index(segment_index)?;
        let lc_off = self.load_commands[lc_idx].offset();
        let nsects = self.segments[segment_index].nsects();
        let insert_at = lc_off + seg_hdr_size + (nsects as usize) * record_size;

        self.buffer
            .splice(insert_at..insert_at, std::iter::repeat_n(0u8, record_size));
        let delta = record_size as i64;

        let order = self.byte_order();
        let new_cmdsize = self.load_commands[lc_idx].cmdsize.value + record_size as u32;
        order.write_u32(&mut self.buffer, lc_off + 4, new_cmdsize);
        order.write_u32(
            &mut self.buffer,
            lc_off + if is_64 { 64 } else { 48 },
            nsects + 1,
        );
        let new_sizeofcmds = self.header.sizeofcmds.value + record_size as u32;
        order.write_u32(&mut self.buffer, 20, new_sizeofcmds);
        self.bump_fileoffs_after_splice(insert_at, delta)?;

        let mut sectname = [0u8; 16];
        let mut segname = [0u8; 16];
        let name_bytes = new.name.as_bytes();
        sectname[..name_bytes.len().min(16)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(16)]);
        let parent = self.segments[segment_index].name();
        let parent_bytes = parent.as_bytes();
        segname[..parent_bytes.len().min(16)]
            .copy_from_slice(&parent_bytes[..parent_bytes.len().min(16)]);

        self.buffer[insert_at..insert_at + 16].copy_from_slice(&sectname);
        self.buffer[insert_at + 16..insert_at + 32].copy_from_slice(&segname);
        if is_64 {
            order.write_u64(&mut self.buffer, insert_at + 32, new.addr);
            order.write_u64(&mut self.buffer, insert_at + 40, new.size);
            order.write_u32(&mut self.buffer, insert_at + 48, new.offset);
            order.write_u32(&mut self.buffer, insert_at + 52, new.align);
            order.write_u32(&mut self.buffer, insert_at + 56, 0);
            order.write_u32(&mut self.buffer, insert_at + 60, 0);
            order.write_u32(&mut self.buffer, insert_at + 64, new.flags);
        } else {
            order.write_u32(&mut self.buffer, insert_at + 32, new.addr as u32);
            order.write_u32(&mut self.buffer, insert_at + 36, new.size as u32);
            order.write_u32(&mut self.buffer, insert_at + 40, new.offset);
            order.write_u32(&mut self.buffer, insert_at + 44, new.align);
            order.write_u32(&mut self.buffer, insert_at + 48, 0);
            order.write_u32(&mut self.buffer, insert_at + 52, 0);
            order.write_u32(&mut self.buffer, insert_at + 56, new.flags);
        }

        self.preserve_code_signature_alignment()?;
        self.reparse()
    }

    fn export_trie_blob(&self) -> Result<Option<&[u8]>, errors::FileParseError> {
        let order = self.byte_order();
        for cmd in &self.load_commands {
            if cmd.cmd.value == LC_DYLD_EXPORTS_TRIE {
                if let Some(TypedCommand::LinkeditData(link)) = cmd.typed(&self.buffer, order)? {
                    let off = link.dataoff.value as usize;
                    let size = link.datasize.value as usize;
                    return Ok(Some(
                        self.buffer
                            .get(off..off + size)
                            .ok_or(errors::FileParseError::BufferOverflow)?,
                    ));
                }
            }
        }
        Ok(None)
    }

    fn load_command_offset(&self, index: usize) -> Result<usize, errors::FileParseError> {
        self.load_commands
            .get(index)
            .map(|c| c.offset())
            .ok_or(errors::FileParseError::BufferOverflow)
    }

    fn segment_lc_index(&self, segment_index: usize) -> Result<usize, errors::FileParseError> {
        let mut n = 0usize;
        for (i, cmd) in self.load_commands.iter().enumerate() {
            if cmd.cmd.value == LC_SEGMENT || cmd.cmd.value == LC_SEGMENT_64 {
                if n == segment_index {
                    return Ok(i);
                }
                n += 1;
            }
        }
        Err(errors::FileParseError::BufferOverflow)
    }

    fn splice_load_region(
        &mut self,
        at: usize,
        remove_len: usize,
        insert: &[u8],
    ) -> Result<(), errors::FileParseError> {
        let delta = insert.len() as i64 - remove_len as i64;
        let min_off = self.min_segment_fileoff() as usize;
        if delta > 0 && at + insert.len() > min_off {
            return Err(errors::FileParseError::BufferOverflow);
        }
        if remove_len > 0 {
            self.buffer.drain(at..at + remove_len);
        }
        if !insert.is_empty() {
            self.buffer.splice(at..at, insert.iter().copied());
        }
        Ok(())
    }

    fn bump_fileoffs_after_splice(
        &mut self,
        at: usize,
        delta: i64,
    ) -> Result<(), errors::FileParseError> {
        if delta == 0 {
            return Ok(());
        }
        self.reparse()?;
        self.bump_fileoffs_from(at, delta)?;
        self.bump_linkedit_from(at, delta)?;
        Ok(())
    }

    fn bump_linkedit_from(&mut self, at: usize, delta: i64) -> Result<(), errors::FileParseError> {
        if delta == 0 {
            return Ok(());
        }
        let order = self.byte_order();
        for cmd in &self.load_commands {
            let off = cmd.cmd.offset;
            match cmd.cmd.value {
                LC_CODE_SIGNATURE | LC_DYLD_EXPORTS_TRIE => {
                    if let Some(TypedCommand::LinkeditData(link)) =
                        cmd.typed(&self.buffer, order)?
                    {
                        if link.dataoff.value as usize >= at {
                            let new_off = if delta > 0 {
                                link.dataoff.value as u64 + delta as u64
                            } else {
                                link.dataoff.value as u64 - (-delta) as u64
                            };
                            order.write_u32(&mut self.buffer, off + 8, new_off as u32);
                        }
                    }
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    if let Some(TypedCommand::DyldInfo(info)) = cmd.typed(&self.buffer, order)? {
                        bump_dyld_info_offsets(&mut self.buffer, &info, off, at, delta, order)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Ensures `LC_CODE_SIGNATURE` `dataoff` stays 16-byte aligned after load-command edits.
    fn preserve_code_signature_alignment(&mut self) -> Result<(), errors::FileParseError> {
        let order = self.byte_order();
        let mut signatures = Vec::new();
        for cmd in &self.load_commands {
            if cmd.cmd.value != LC_CODE_SIGNATURE {
                continue;
            }
            if let Some(TypedCommand::LinkeditData(sig)) = cmd.typed(&self.buffer, order)? {
                signatures.push((cmd.offset(), sig.dataoff.value as usize));
            }
        }
        for (cmd_off, dataoff) in signatures {
            let misalign = dataoff % 16;
            if misalign == 0 {
                continue;
            }
            let pad = 16 - misalign;
            let lc_end = self.header_size() + self.header.sizeofcmds.value as usize;
            self.buffer
                .splice(lc_end..lc_end, std::iter::repeat_n(0u8, pad));
            self.bump_fileoffs_from(lc_end, pad as i64)?;
            let new_off = dataoff + pad;
            order.write_u32(&mut self.buffer, cmd_off + 8, new_off as u32);
        }
        Ok(())
    }

    fn bump_fileoffs_from(&mut self, at: usize, delta: i64) -> Result<(), errors::FileParseError> {
        if delta == 0 {
            return Ok(());
        }
        let order = self.byte_order();
        for seg in &mut self.segments {
            if seg.fileoff() as usize >= at {
                let new_off = if delta > 0 {
                    seg.fileoff() + delta as u64
                } else {
                    seg.fileoff().saturating_sub((-delta) as u64)
                };
                seg.fileoff_mut()
                    .update_with(&mut self.buffer, new_off, order)?;
            }
        }
        Ok(())
    }

    fn header_size(&self) -> usize {
        if self.header.reserved.is_some() {
            32
        } else {
            28
        }
    }

    fn is_64bit(&self) -> bool {
        self.header.reserved.is_some()
    }

    fn reparse(&mut self) -> Result<(), errors::FileParseError> {
        let buf = std::mem::take(&mut self.buffer);
        *self = Self::from_buffer(buf)?;
        Ok(())
    }

    fn min_segment_fileoff(&self) -> u64 {
        self.segments
            .iter()
            .map(|s| s.fileoff())
            .filter(|&v| v > 0)
            .min()
            .unwrap_or(self.buffer.len() as u64)
    }

    /// Appends a new `LC_SEGMENT` or `LC_SEGMENT_64` load command and segment data.
    pub fn insert_segment(&mut self, new: NewSegment) -> Result<(), errors::FileParseError> {
        let order = self.byte_order();
        let is_64 = self.is_64bit();
        let hdr_size = self.header_size();
        let lc_end = hdr_size + self.header.sizeofcmds.value as usize;
        let cmd_size = if is_64 { 72 } else { 56 };
        let min_off = self.min_segment_fileoff() as usize;

        if lc_end + cmd_size > min_off {
            self.buffer
                .splice(lc_end..lc_end, std::iter::repeat_n(0u8, cmd_size));
            self.bump_fileoffs_from(lc_end, cmd_size as i64)?;
        }

        let lc_base = lc_end;
        let data_offset = self.buffer.len() as u64;
        self.buffer.extend_from_slice(&new.data);

        let mut segname = [0u8; 16];
        let name_bytes = new.name.as_bytes();
        let copy_len = name_bytes.len().min(16);
        segname[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        order.write_u32(
            &mut self.buffer,
            lc_base,
            if is_64 { LC_SEGMENT_64 } else { LC_SEGMENT },
        );
        order.write_u32(&mut self.buffer, lc_base + 4, cmd_size as u32);
        self.buffer[lc_base + 8..lc_base + 24].copy_from_slice(&segname);

        if is_64 {
            order.write_u64(&mut self.buffer, lc_base + 24, 0);
            order.write_u64(&mut self.buffer, lc_base + 32, new.data.len() as u64);
            order.write_u64(&mut self.buffer, lc_base + 40, data_offset);
            order.write_u64(&mut self.buffer, lc_base + 48, new.data.len() as u64);
            order.write_u32(&mut self.buffer, lc_base + 56, new.maxprot);
            order.write_u32(&mut self.buffer, lc_base + 60, new.initprot);
            order.write_u32(&mut self.buffer, lc_base + 64, 0);
            order.write_u32(&mut self.buffer, lc_base + 68, 0);
        } else {
            order.write_u32(&mut self.buffer, lc_base + 24, 0);
            order.write_u32(&mut self.buffer, lc_base + 28, new.data.len() as u32);
            order.write_u32(&mut self.buffer, lc_base + 32, data_offset as u32);
            order.write_u32(&mut self.buffer, lc_base + 36, new.data.len() as u32);
            order.write_u32(&mut self.buffer, lc_base + 40, new.maxprot);
            order.write_u32(&mut self.buffer, lc_base + 44, new.initprot);
            order.write_u32(&mut self.buffer, lc_base + 48, 0);
            order.write_u32(&mut self.buffer, lc_base + 52, 0);
        }

        let new_ncmds = self.header.ncmds.value + 1;
        let new_sizeofcmds = self.header.sizeofcmds.value + cmd_size as u32;
        order.write_u32(&mut self.buffer, 16, new_ncmds);
        order.write_u32(&mut self.buffer, 20, new_sizeofcmds);

        self.reparse()
    }
}

fn bump_dyld_info_offsets(
    buffer: &mut [u8],
    info: &DyldInfoCommand,
    cmd_off: usize,
    at: usize,
    delta: i64,
    order: ByteOrder,
) -> Result<(), errors::FileParseError> {
    let fields: [(u32, usize); 5] = [
        (info.rebase_off.value, cmd_off + 8),
        (info.bind_off.value, cmd_off + 16),
        (info.weak_bind_off.value, cmd_off + 24),
        (info.lazy_bind_off.value, cmd_off + 32),
        (info.export_off.value, cmd_off + 40),
    ];
    for (value, field_off) in fields {
        if value as usize >= at {
            let new_val = if delta > 0 {
                value + delta as u32
            } else {
                value - (-delta) as u32
            };
            order.write_u32(buffer, field_off, new_val);
        }
    }
    Ok(())
}
