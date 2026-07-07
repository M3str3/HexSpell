//! Per-format relocation listing helpers.
//!
//! HexSpell does not unify relocation types across PE, ELF, and Mach-O — each format keeps its own
//! entry layout. This module documents the mapping and provides thin filters by RVA/VA or file
//! offset.
//!
//! | Format | Source | Address field | Types |
//! |--------|--------|---------------|-------|
//! | PE | `.reloc` / `IMAGE_BASE_RELOCATION` | page RVA + 12-bit offset | `IMAGE_REL_BASED_*` |
//! | PE | section `IMAGE_RELOCATION` | RVA per entry | `IMAGE_REL_I386_*` / `IMAGE_REL_AMD64_*` |
//! | ELF | `.rel` / `.rela` sections | `r_offset` (VA) | arch-specific `R_*` in `r_info` |
//! | Mach-O | `section.reloff` | section-relative offset | `relocation_info` (not decoded yet) |

use crate::elf::relocation::RelocationEntry;
use crate::elf::ELF;
use crate::errors::FileParseError;
use crate::pe::relocation::{BaseRelocationBlock, BaseRelocationEntry};
use crate::pe::section_reloc::SectionRelocation;
use crate::pe::PE;

/// One PE base relocation targeting a specific RVA.
#[derive(Debug, Clone)]
pub struct PeBaseRelocHit {
    pub page_rva: u32,
    pub rva: u32,
    pub file_offset: usize,
    pub entry: BaseRelocationEntry,
}

/// One PE COFF section relocation targeting a specific RVA.
#[derive(Debug, Clone)]
pub struct PeSectionRelocHit {
    pub section_index: usize,
    pub rva: u32,
    pub file_offset: usize,
    pub entry: SectionRelocation,
}

/// ELF relocation with the owning section index.
#[derive(Debug, Clone)]
pub struct ElfRelocHit {
    pub section_index: usize,
    pub entry: RelocationEntry,
}

/// Lists PE base relocations whose patched RVA equals `rva`.
pub fn pe_base_relocs_at_rva(pe: &PE, rva: u32) -> Result<Vec<PeBaseRelocHit>, FileParseError> {
    let mut hits = Vec::new();
    for block in &pe.base_relocations {
        for entry in &block.entries {
            let entry_rva = entry.rva(block.page_rva.value);
            if entry_rva == rva {
                hits.push(PeBaseRelocHit {
                    page_rva: block.page_rva.value,
                    rva: entry_rva,
                    file_offset: pe.rva_to_offset(entry_rva)?,
                    entry: BaseRelocationEntry {
                        raw: entry.raw.clone(),
                    },
                });
            }
        }
    }
    Ok(hits)
}

/// Lists every PE base relocation entry (eager directory already parsed on [`PE`]).
pub fn pe_base_relocs(pe: &PE) -> Vec<PeBaseRelocHit> {
    let mut hits = Vec::new();
    for block in &pe.base_relocations {
        for entry in &block.entries {
            let rva = entry.rva(block.page_rva.value);
            let file_offset = pe.rva_to_offset(rva).unwrap_or(0);
            hits.push(PeBaseRelocHit {
                page_rva: block.page_rva.value,
                rva,
                file_offset,
                entry: BaseRelocationEntry {
                    raw: entry.raw.clone(),
                },
            });
        }
    }
    hits
}

/// Lists PE COFF section relocations at `rva` across all sections.
pub fn pe_section_relocs_at_rva(
    pe: &PE,
    rva: u32,
) -> Result<Vec<PeSectionRelocHit>, FileParseError> {
    let mut hits = Vec::new();
    for index in 0..pe.sections.len() {
        let block = pe.section_relocations(index)?;
        for entry in block.entries {
            if entry.virtual_address.value == rva {
                hits.push(PeSectionRelocHit {
                    section_index: index,
                    rva,
                    file_offset: pe.rva_to_offset(rva)?,
                    entry,
                });
            }
        }
    }
    Ok(hits)
}

/// Lists PE base relocations whose patched slot maps to `file_offset`.
pub fn pe_relocs_at_file_offset(
    pe: &PE,
    file_offset: usize,
) -> Result<Vec<PeBaseRelocHit>, FileParseError> {
    let mut hits = Vec::new();
    for block in &pe.base_relocations {
        for entry in &block.entries {
            let rva = entry.rva(block.page_rva.value);
            let off = pe.rva_to_offset(rva)?;
            if off == file_offset {
                hits.push(PeBaseRelocHit {
                    page_rva: block.page_rva.value,
                    rva,
                    file_offset: off,
                    entry: BaseRelocationEntry {
                        raw: entry.raw.clone(),
                    },
                });
            }
        }
    }
    Ok(hits)
}

/// Lists ELF relocations whose `r_offset` equals `va`.
pub fn elf_relocs_at_va(elf: &ELF, va: u64) -> Result<Vec<ElfRelocHit>, FileParseError> {
    let mut hits = Vec::new();
    for (section_index, entries) in elf.relocations()? {
        for entry in entries {
            if entry.r_offset() == va {
                hits.push(ElfRelocHit {
                    section_index,
                    entry,
                });
            }
        }
    }
    Ok(hits)
}

/// Lists ELF relocations whose `r_offset` maps to `file_offset` via [`crate::validation::elf_va_to_file_offset`].
pub fn elf_relocs_at_file_offset(
    elf: &ELF,
    file_offset: usize,
) -> Result<Vec<ElfRelocHit>, FileParseError> {
    let mut hits = Vec::new();
    for (section_index, entries) in elf.relocations()? {
        for entry in entries {
            let va = entry.r_offset();
            if crate::validation::elf_va_to_file_offset(elf, va)? == file_offset {
                hits.push(ElfRelocHit {
                    section_index,
                    entry,
                });
            }
        }
    }
    Ok(hits)
}

/// Re-parses the PE base relocation directory from the image (lazy alternative to [`PE::base_relocations`]).
pub fn pe_parse_base_relocations(pe: &PE) -> Result<Vec<BaseRelocationBlock>, FileParseError> {
    use crate::pe::header::BASERELOC;
    if !pe.optional_header.has_data_directory(BASERELOC) {
        return Ok(Vec::new());
    }
    let directory = &pe.optional_header.data_directories[BASERELOC];
    if directory.virtual_address.value == 0 || directory.size.value == 0 {
        return Ok(Vec::new());
    }
    let offset = pe.rva_to_offset(directory.virtual_address.value)?;
    crate::pe::relocation::parse_base_relocations(&pe.buffer, offset, directory.size.value as usize)
}
