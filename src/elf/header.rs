//! Definitions relating to the ELF file header.
//!
//! The file header contains global information about the binary such as
//! its architecture, entry point and endianness. This module models that
//! data using [`Field`] so the underlying bytes can be
//! changed safely. Helper methods interpret raw numeric values into more
//! meaningful enums, reducing boilerplate for consumers of the crate.

use crate::errors;
use crate::field::{ByteOrder, Field, FixedBytes};

/// ELF file type (`e_type`).
#[derive(Debug, PartialEq, Eq)]
pub enum ElfType {
    None,
    Relocatable,
    Executable,
    SharedObject,
    Core,
    Other(u16),
}

impl From<u16> for ElfType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::SharedObject,
            4 => Self::Core,
            _ => Self::Other(value),
        }
    }
}

/// ELF word size (`EI_CLASS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    /// 32-bit ELF.
    Elf32,
    /// 64-bit ELF.
    Elf64,
}

/// ELF file header (`Ehdr`).
///
/// `ei_mag`, `ei_class`, `ei_data`, `ei_version`, and `ei_pad` mirror `e_ident`. Use
/// [`ElfHeader::ei_data`] as the canonical endianness byte (`1` = LE, `2` = BE).
#[derive(Debug)]
pub struct ElfHeader {
    /// `e_ident[0..4]` — must be `\x7FELF`.
    pub ei_mag: Field<FixedBytes<4>>,
    /// `e_ident[EI_CLASS]` — `1` = ELF32, `2` = ELF64.
    pub ei_class: Field<u8>,
    /// `e_ident[EI_DATA]` — `1` = little-endian, `2` = big-endian.
    pub ei_data: Field<u8>,
    /// `e_ident[EI_VERSION]`.
    pub ei_version: Field<u8>,
    /// `e_ident[EI_PAD..]` — padding bytes.
    pub ei_pad: Field<FixedBytes<9>>,
    /// `e_type`.
    pub elf_type: Field<ElfType>,
    /// `e_machine`.
    pub machine: Field<u16>,
    /// `e_version`.
    pub version: Field<u32>,
    /// `e_entry` — program entry point virtual address.
    pub entry: Field<u64>,
    /// `e_phoff` — file offset of the program header table.
    pub ph_off: Field<u64>,
    /// `e_shoff` — file offset of the section header table.
    pub sh_off: Field<u64>,
    /// `e_flags`.
    pub flags: Field<u32>,
    /// `e_ehsize`.
    pub eh_size: Field<u16>,
    /// `e_phentsize`.
    pub ph_ent_size: Field<u16>,
    /// `e_phnum`.
    pub ph_num: Field<u16>,
    /// `e_shentsize`.
    pub sh_ent_size: Field<u16>,
    /// `e_shnum`.
    pub sh_num: Field<u16>,
    /// `e_shstrndx` — section header string table index.
    pub sh_strndx: Field<u16>,
}

impl ElfHeader {
    /// Returns [`ElfClass`] from `ei_class`.
    pub fn class(&self) -> Result<ElfClass, errors::FileParseError> {
        match self.ei_class.value {
            1 => Ok(ElfClass::Elf32),
            2 => Ok(ElfClass::Elf64),
            _ => Err(errors::FileParseError::InvalidFileFormat),
        }
    }

    /// Parses the ELF file header from the start of `buffer`.
    pub fn parse(buffer: &[u8]) -> Result<Self, errors::FileParseError> {
        if buffer.len() < 16 {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let ei_mag = Field::new(FixedBytes::from_slice(&buffer[0..4]), 0, 4);
        let ei_class = Field::new(buffer[4], 4, 1);
        let ei_data = Field::new(buffer[5], 5, 1);
        let ei_version = Field::new(buffer[6], 6, 1);
        let ei_pad = Field::new(FixedBytes::from_slice(&buffer[7..16]), 7, 9);

        if ei_mag.value.0 != [0x7F, b'E', b'L', b'F'] {
            return Err(errors::FileParseError::InvalidFileFormat);
        }

        let class = match ei_class.value {
            1 => ElfClass::Elf32,
            2 => ElfClass::Elf64,
            _ => return Err(errors::FileParseError::InvalidFileFormat),
        };

        let order = ByteOrder::from_ei_data(ei_data.value)?;

        let min_header_size = match class {
            ElfClass::Elf32 => 52,
            ElfClass::Elf64 => 64,
        };
        if buffer.len() < min_header_size {
            return Err(errors::FileParseError::BufferOverflow);
        }

        let elf_type: Field<ElfType> =
            Field::new(ElfType::from(order.read_u16(buffer, 16)?), 16, 2);
        let machine: Field<u16> = Field::new(order.read_u16(buffer, 18)?, 18, 2);
        let version: Field<u32> = Field::new(order.read_u32(buffer, 20)?, 20, 4);

        let (
            entry,
            ph_off,
            sh_off,
            flags,
            eh_size,
            ph_ent_size,
            ph_num,
            sh_ent_size,
            sh_num,
            sh_strndx,
        ) = match class {
            ElfClass::Elf32 => (
                Field::new(order.read_u32(buffer, 24)? as u64, 24, 4),
                Field::new(order.read_u32(buffer, 28)? as u64, 28, 4),
                Field::new(order.read_u32(buffer, 32)? as u64, 32, 4),
                Field::new(order.read_u32(buffer, 36)?, 36, 4),
                Field::new(order.read_u16(buffer, 40)?, 40, 2),
                Field::new(order.read_u16(buffer, 42)?, 42, 2),
                Field::new(order.read_u16(buffer, 44)?, 44, 2),
                Field::new(order.read_u16(buffer, 46)?, 46, 2),
                Field::new(order.read_u16(buffer, 48)?, 48, 2),
                Field::new(order.read_u16(buffer, 50)?, 50, 2),
            ),
            ElfClass::Elf64 => (
                Field::new(order.read_u64(buffer, 24)?, 24, 8),
                Field::new(order.read_u64(buffer, 32)?, 32, 8),
                Field::new(order.read_u64(buffer, 40)?, 40, 8),
                Field::new(order.read_u32(buffer, 48)?, 48, 4),
                Field::new(order.read_u16(buffer, 52)?, 52, 2),
                Field::new(order.read_u16(buffer, 54)?, 54, 2),
                Field::new(order.read_u16(buffer, 56)?, 56, 2),
                Field::new(order.read_u16(buffer, 58)?, 58, 2),
                Field::new(order.read_u16(buffer, 60)?, 60, 2),
                Field::new(order.read_u16(buffer, 62)?, 62, 2),
            ),
        };

        Ok(ElfHeader {
            ei_mag,
            ei_class,
            ei_data,
            ei_version,
            ei_pad,
            elf_type,
            machine,
            version,
            entry,
            ph_off,
            sh_off,
            flags,
            eh_size,
            ph_ent_size,
            ph_num,
            sh_ent_size,
            sh_num,
            sh_strndx,
        })
    }
}
