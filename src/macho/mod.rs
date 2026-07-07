//! Facilities for reading and modifying Mach-O binaries.
//!
//! FAT wrappers are unpacked automatically; [`MachO`] always refers to a thin Mach-O image.
//! Byte order is derived from the magic bytes at file offset 0 — there is no endianness field in
//! the header.

pub mod fat;
pub mod header;
pub mod load_command;
pub mod section;
pub mod segment;
pub mod symbol;

use crate::errors;
use crate::field::ByteOrder;
use header::MachHeader;
use load_command::{LoadCommand, TypedCommand, LC_SEGMENT, LC_SEGMENT_64};
use section::SectionEntry;
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

    fn bump_fileoffs_from(&mut self, at: usize, delta: i64) -> Result<(), errors::FileParseError> {
        if delta == 0 {
            return Ok(());
        }
        let delta_u = delta as u64;
        let order = self.byte_order();
        for seg in &mut self.segments {
            if seg.fileoff() as usize >= at {
                let new_off = seg.fileoff() + delta_u;
                seg.fileoff_mut()
                    .update_with(&mut self.buffer, new_off, order)?;
            }
        }
        Ok(())
    }
}
