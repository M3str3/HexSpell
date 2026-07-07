//! Minimal write/layout planning helpers (P2).
//!
//! Structural edits (`insert_section`, `insert_segment`, …) mutate the buffer immediately. These
//! helpers compute the resulting layout **before** applying changes so callers can preview growth
//! or bail out early.

use crate::errors::FileParseError;
use crate::pe::section::NewSection;
use crate::pe::PE;

/// Planned outcome of appending a PE section (mirrors [`PE::insert_section`] sizing rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInsertSectionPlan {
    /// New section header offset in the file.
    pub section_header_offset: usize,
    /// RVA of the new section.
    pub virtual_address: u32,
    /// File offset of raw section data.
    pub raw_data_offset: u32,
    /// Padded raw size on disk.
    pub size_of_raw_data: u32,
    /// Total buffer length after the insert.
    pub new_buffer_len: usize,
}

/// Computes where a new PE section would be placed without mutating `pe`.
pub fn plan_pe_insert_section(
    pe: &PE,
    new: &NewSection,
) -> Result<PeInsertSectionPlan, FileParseError> {
    let file_alignment = pe.optional_header.file_alignment.value;
    let section_alignment = pe.optional_header.section_alignment.value;

    let last_section = pe
        .sections
        .last()
        .ok_or(FileParseError::InvalidFileFormat)?;

    let section_header_offset =
        last_section.characteristics.offset + last_section.characteristics.size;
    let virtual_address =
        (last_section.virtual_address.value + last_section.virtual_size.value + section_alignment
            - 1)
            & !(section_alignment - 1);
    let _virtual_size = (new.data.len() as u32 + section_alignment - 1) & !(section_alignment - 1);
    let size_of_raw_data = (new.data.len() as u32 + file_alignment - 1) & !(file_alignment - 1);
    let raw_data_offset = (last_section.pointer_to_raw_data.value
        + last_section.size_of_raw_data.value
        + file_alignment
        - 1)
        & !(file_alignment - 1);

    let new_buffer_len = raw_data_offset as usize + size_of_raw_data as usize;

    Ok(PeInsertSectionPlan {
        section_header_offset,
        virtual_address,
        raw_data_offset,
        size_of_raw_data,
        new_buffer_len,
    })
}

/// When `true`, a planned structural edit should only be simulated (caller checks this flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WriteMode {
    /// Apply mutations to the in-memory buffer (default for `insert_*` APIs).
    #[default]
    Live,
    /// Caller inspects a [`PeInsertSectionPlan`] (or similar) and skips mutation.
    DryRun,
}

impl WriteMode {
    /// Returns `true` for [`WriteMode::DryRun`].
    pub fn is_dry_run(self) -> bool {
        matches!(self, WriteMode::DryRun)
    }
}
