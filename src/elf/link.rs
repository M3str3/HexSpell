//! ELF section linkage helpers.

/// A section identified by role, index, `sh_link`, and `sh_addr`.
pub struct LinkedSection {
    /// Conventional role such as `.plt`, `.got`, or `.got.plt`.
    pub role: String,
    /// Section index.
    pub section_index: usize,
    /// Linked section index from `sh_link`.
    pub link: u32,
    /// Virtual address from `sh_addr`.
    pub addr: u64,
}
