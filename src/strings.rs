//! Cross-format NUL-terminated string helpers.
//!
//! PE import/export names, PE long section names (`/offset` into the COFF string table), and
//! Mach-O symtab / dylib cstring pools share the same on-disk encoding. This module centralizes
//! reading and exposes thin per-format wrappers.

use crate::errors::FileParseError;
use crate::macho::MachO;
use crate::pe::import::{ImportDirectory, ImportEntry};
use crate::pe::PE;

/// Reads a NUL-terminated string at an absolute file offset.
///
/// Invalid UTF-8 is decoded lossily (same policy as ELF `.strtab` resolution).
pub fn read_c_string(buffer: &[u8], offset: usize) -> Result<String, FileParseError> {
    let tail = buffer.get(offset..).ok_or(FileParseError::BufferOverflow)?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(FileParseError::InvalidFileFormat)?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// Reads a string inside a cstring pool (`stroff` .. `stroff + strsize`).
///
/// Index `0` is the empty name per Mach-O / COFF conventions.
pub fn read_c_string_in_pool(
    buffer: &[u8],
    pool_offset: usize,
    pool_size: usize,
    index: usize,
) -> Result<String, FileParseError> {
    if index == 0 || index >= pool_size {
        return Ok(String::new());
    }
    let start = pool_offset + index;
    let end = pool_offset + pool_size;
    let slice = buffer
        .get(start..end)
        .ok_or(FileParseError::BufferOverflow)?;
    let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..stop]).into_owned())
}

/// View of a Mach-O `LC_SYMTAB` string pool.
#[derive(Debug, Clone, Copy)]
pub struct CStringPool {
    /// Absolute file offset of the pool (Mach-O `stroff`).
    pub offset: usize,
    /// Pool size in bytes (Mach-O `strsize`).
    pub size: usize,
}

impl CStringPool {
    /// Resolves `index` inside this pool.
    pub fn resolve(&self, buffer: &[u8], index: usize) -> Result<String, FileParseError> {
        read_c_string_in_pool(buffer, self.offset, self.size, index)
    }
}

/// Resolves a PE section name, including COFF long names (`/123` → string table offset).
pub fn pe_section_name(pe: &PE, index: usize) -> Result<String, FileParseError> {
    let section = pe
        .sections
        .get(index)
        .ok_or(FileParseError::BufferOverflow)?;
    let raw = section.name_str();
    if let Some(digits) = raw.strip_prefix('/') {
        if digits.is_empty() {
            return Err(FileParseError::InvalidFileFormat);
        }
        let str_index: usize = digits
            .parse()
            .map_err(|_| FileParseError::InvalidFileFormat)?;
        let symtab = pe.coff_symbols()?;
        if symtab.string_table_offset == 0 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let name_off = symtab
            .string_table_offset
            .checked_add(4)
            .and_then(|base| base.checked_add(str_index))
            .ok_or(FileParseError::BufferOverflow)?;
        return read_c_string(&pe.buffer, name_off);
    }
    Ok(raw.to_owned())
}

/// Collects DLL names and imported symbol names from the PE import directory.
pub fn pe_import_strings(pe: &PE) -> Result<Vec<(String, Vec<String>)>, FileParseError> {
    let imports = pe.imports()?;
    Ok(pe_import_strings_from_directory(&imports))
}

/// Same as [`pe_import_strings`] but reuses a parsed [`ImportDirectory`].
pub fn pe_import_strings_from_directory(imports: &ImportDirectory) -> Vec<(String, Vec<String>)> {
    imports
        .dlls
        .iter()
        .map(|dll| {
            let names = dll
                .entries
                .iter()
                .filter_map(|entry| match entry {
                    ImportEntry::ByName { by_name, .. } => Some(by_name.name.clone()),
                    ImportEntry::Ordinal { ordinal, .. } => Some(format!("#{}", ordinal)),
                })
                .collect();
            (dll.dll_name.clone(), names)
        })
        .collect()
}

/// Returns exported symbol names when an export directory is present.
pub fn pe_export_names(pe: &PE) -> Result<Vec<String>, FileParseError> {
    let Some(exports) = pe.exports()? else {
        return Ok(Vec::new());
    };
    Ok(exports.named.iter().map(|e| e.name.clone()).collect())
}

/// Returns the Mach-O symtab cstring pool when `LC_SYMTAB` is present.
pub fn macho_symtab_string_pool(macho: &MachO) -> Result<Option<CStringPool>, FileParseError> {
    use crate::macho::load_command::TypedCommand;
    let order = macho.byte_order();
    for cmd in &macho.load_commands {
        if let Some(TypedCommand::Symtab(symtab)) = cmd.typed(&macho.buffer, order)? {
            return Ok(Some(CStringPool {
                offset: symtab.stroff.value as usize,
                size: symtab.strsize.value as usize,
            }));
        }
    }
    Ok(None)
}

/// Resolves every dylib path referenced by load commands (weak / re-export / lazy included).
pub fn macho_dylib_paths(macho: &MachO) -> Result<Vec<String>, FileParseError> {
    macho.linked_dylibs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_c_string_in_pool_empty_index() {
        let buf = b"\0hello\0";
        assert_eq!(read_c_string_in_pool(buf, 0, buf.len(), 0).unwrap(), "");
    }

    #[test]
    fn read_c_string_in_pool_resolves_entry() {
        let buf = b"\0hello\0";
        assert_eq!(
            read_c_string_in_pool(buf, 0, buf.len(), 1).unwrap(),
            "hello"
        );
    }
}
