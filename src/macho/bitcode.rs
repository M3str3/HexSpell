//! Bitcode bundle detection (`__LLVM` segment).
//!
//! LLVM bitcode is stored in a `__LLVM` segment (often with a `__bundle` section). HexSpell exposes
//! the segment and its sections as parsed layout entries — it does not decode the bitcode IR.

use super::section::SectionEntry;
use super::segment::SegmentEntry;

/// Name of the LLVM bitcode segment in Mach-O images.
pub const LLVM_SEGMENT_NAME: &str = "__LLVM";

/// Typical section name holding the bitcode bundle.
pub const LLVM_BUNDLE_SECTION: &str = "__bundle";

/// Returns the `__LLVM` segment, if present.
pub fn llvm_segment<'a>(segments: &'a [SegmentEntry]) -> Option<&'a SegmentEntry> {
    segments
        .iter()
        .find(|s| s.name().trim_end_matches('\0') == LLVM_SEGMENT_NAME)
}

/// Returns every section nested under the `__LLVM` segment.
pub fn llvm_sections<'a>(
    _segments: &'a [SegmentEntry],
    sections: &'a [SectionEntry],
) -> Vec<&'a SectionEntry> {
    sections
        .iter()
        .filter(|s| s.segment_name().trim_end_matches('\0') == LLVM_SEGMENT_NAME)
        .collect()
}
