//! Cross-format validation: file-range overlap detection, VA/file-offset translation, and
//! lightweight consistency checks.

use crate::elf::ELF;
use crate::errors::FileParseError;
use crate::macho::MachO;
use crate::pe::header::ImageBase;
use crate::pe::PE;

/// Half-open file byte range `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRange {
    /// Human-readable label (section name, segment name, etc.).
    pub label: String,
    /// Inclusive start offset.
    pub start: usize,
    /// Exclusive end offset.
    pub end: usize,
}

impl FileRange {
    /// Returns `true` when this range overlaps `other` (touching edges do not count).
    pub fn overlaps(&self, other: &FileRange) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Pair of overlapping [`FileRange`] values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlap {
    pub a: FileRange,
    pub b: FileRange,
}

/// Returns every overlapping pair in `ranges` (O(n²); intended for small tables).
pub fn find_overlaps(ranges: &[FileRange]) -> Vec<Overlap> {
    let mut out = Vec::new();
    for i in 0..ranges.len() {
        for j in (i + 1)..ranges.len() {
            if ranges[i].overlaps(&ranges[j]) {
                out.push(Overlap {
                    a: ranges[i].clone(),
                    b: ranges[j].clone(),
                });
            }
        }
    }
    out
}

/// File-backed PE section ranges (`PointerToRawData` .. `+SizeOfRawData`).
pub fn pe_file_ranges(pe: &PE) -> Vec<FileRange> {
    pe.sections
        .iter()
        .enumerate()
        .filter_map(|(i, section)| {
            let start = section.pointer_to_raw_data.value as usize;
            let size = section.size_of_raw_data.value as usize;
            if size == 0 {
                return None;
            }
            let end = start.checked_add(size)?;
            Some(FileRange {
                label: format!("section[{i}] {}", section.name_str()),
                start,
                end,
            })
        })
        .collect()
}

/// File-backed ELF section ranges (`sh_offset` .. `+sh_size`, skipping `SHT_NOBITS`).
pub fn elf_file_ranges(elf: &ELF) -> Vec<FileRange> {
    elf.section_headers
        .iter()
        .enumerate()
        .filter_map(|(i, sh)| {
            if sh.sh_type() == crate::elf::section::SHT_NOBITS {
                return None;
            }
            let start = sh.sh_offset() as usize;
            let size = sh.sh_size() as usize;
            if size == 0 {
                return None;
            }
            let end = start.checked_add(size)?;
            let label = elf
                .section_name(i)
                .unwrap_or_else(|_| format!("section[{i}]"));
            Some(FileRange { label, start, end })
        })
        .collect()
}

/// File-backed Mach-O segment ranges (`fileoff` .. `+filesize`).
pub fn macho_file_ranges(macho: &MachO) -> Vec<FileRange> {
    macho
        .segments
        .iter()
        .filter_map(|seg| {
            let start = seg.fileoff() as usize;
            let size = seg.filesize() as usize;
            if size == 0 {
                return None;
            }
            let end = start.checked_add(size)?;
            Some(FileRange {
                label: seg.name().to_string(),
                start,
                end,
            })
        })
        .collect()
}

/// Maps a PE RVA to a file offset (wrapper around [`PE::rva_to_offset`]).
pub fn pe_rva_to_file_offset(pe: &PE, rva: u32) -> Result<usize, FileParseError> {
    pe.rva_to_offset(rva)
}

/// Maps a PE VA (preferred image base + RVA) to a file offset.
pub fn pe_va_to_file_offset(pe: &PE, va: u64) -> Result<usize, FileParseError> {
    let base = match pe.optional_header.image_base.value {
        ImageBase::Base32(v) => v as u64,
        ImageBase::Base64(v) => v,
    };
    if va < base {
        return Err(FileParseError::InvalidFileFormat);
    }
    let rva = u32::try_from(va - base).map_err(|_| FileParseError::ValueTooLarge)?;
    pe.rva_to_offset(rva)
}

/// Maps an ELF virtual address to a file offset using `PT_LOAD` segments.
pub fn elf_va_to_file_offset(elf: &ELF, va: u64) -> Result<usize, FileParseError> {
    for ph in &elf.program_headers {
        if ph.p_type() != crate::elf::program::PT_LOAD {
            continue;
        }
        let vaddr = ph.p_vaddr();
        let memsz = ph.p_memsz();
        if va >= vaddr && va < vaddr + memsz {
            let delta = va - vaddr;
            if delta > ph.p_filesz() {
                return Err(FileParseError::BufferOverflow);
            }
            return ph
                .p_offset()
                .checked_add(delta)
                .and_then(|off| usize::try_from(off).ok())
                .ok_or(FileParseError::BufferOverflow);
        }
    }
    Err(FileParseError::InvalidFileFormat)
}

/// Maps a Mach-O virtual address to a file offset using segment load commands.
pub fn macho_va_to_file_offset(macho: &MachO, va: u64) -> Result<usize, FileParseError> {
    for seg in &macho.segments {
        let base = seg.vmaddr();
        let size = seg.vmsize();
        if va >= base && va < base + size {
            let delta = va - base;
            if delta > seg.filesize() {
                return Err(FileParseError::BufferOverflow);
            }
            return seg
                .fileoff()
                .checked_add(delta)
                .and_then(|off| usize::try_from(off).ok())
                .ok_or(FileParseError::BufferOverflow);
        }
    }
    Err(FileParseError::InvalidFileFormat)
}

/// Non-fatal consistency issue surfaced by validation helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub message: String,
}

/// Checks PE header/section invariants that HexSpell relies on when patching.
pub fn pe_consistency(pe: &PE) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    let expected_optional = pe.coff_header.size_of_optional_header.value as usize;
    if expected_optional == 0 {
        issues.push(ValidationIssue {
            message: "size_of_optional_header is zero".into(),
        });
    }

    let sections_end = pe
        .sections
        .last()
        .map(|s| s.characteristics.offset + s.characteristics.size)
        .unwrap_or(0);
    if sections_end > pe.optional_header.size_of_headers.value as usize {
        issues.push(ValidationIssue {
            message: format!(
                "section table extends past SizeOfHeaders (table ends at {sections_end:#x}, SizeOfHeaders {:#x})",
                pe.optional_header.size_of_headers.value
            ),
        });
    }

    for overlap in find_overlaps(&pe_file_ranges(pe)) {
        issues.push(ValidationIssue {
            message: format!(
                "overlapping section file ranges: {} [{:#x}-{:#x}) vs {} [{:#x}-{:#x})",
                overlap.a.label,
                overlap.a.start,
                overlap.a.end,
                overlap.b.label,
                overlap.b.start,
                overlap.b.end
            ),
        });
    }

    issues
}

/// Checks ELF program/section header consistency.
pub fn elf_consistency(elf: &ELF) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    let ph_end = elf.header.ph_off.value as usize
        + elf.header.ph_num.value as usize * elf.header.ph_ent_size.value as usize;
    if ph_end > elf.buffer.len() {
        issues.push(ValidationIssue {
            message: format!("program header table extends past EOF ({ph_end:#x})"),
        });
    }

    let sh_end = elf.header.sh_off.value as usize
        + elf.header.sh_num.value as usize * elf.header.sh_ent_size.value as usize;
    if sh_end > elf.buffer.len() {
        issues.push(ValidationIssue {
            message: format!("section header table extends past EOF ({sh_end:#x})"),
        });
    }

    for overlap in find_overlaps(&elf_file_ranges(elf)) {
        issues.push(ValidationIssue {
            message: format!(
                "overlapping section file ranges: {} vs {}",
                overlap.a.label, overlap.b.label
            ),
        });
    }

    issues
}

/// Checks Mach-O load-command size accounting.
pub fn macho_consistency(macho: &MachO) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    let hdr_size = if macho.header.reserved.is_some() {
        32
    } else {
        28
    };
    let lc_end = hdr_size + macho.header.sizeofcmds.value as usize;
    if lc_end > macho.buffer.len() {
        issues.push(ValidationIssue {
            message: format!("load commands extend past EOF ({lc_end:#x})"),
        });
    }

    let sum: u32 = macho.load_commands.iter().map(|lc| lc.cmdsize.value).sum();
    if sum != macho.header.sizeofcmds.value {
        issues.push(ValidationIssue {
            message: format!(
                "sizeofcmds ({:#x}) does not equal sum of cmdsize ({:#x})",
                macho.header.sizeofcmds.value, sum
            ),
        });
    }

    for overlap in find_overlaps(&macho_file_ranges(macho)) {
        issues.push(ValidationIssue {
            message: format!(
                "overlapping segment file ranges: {} vs {}",
                overlap.a.label, overlap.b.label
            ),
        });
    }

    issues
}
