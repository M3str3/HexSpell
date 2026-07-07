//! Types and parsers for Mach-O load commands.
//!
//! [`LoadCommand`] keeps the raw `cmd` + `cmdsize` header for every entry. Commands whose payload
//! HexSpell models are additionally exposed as typed views through [`LoadCommand::typed`] and the
//! per-kind parsers in this module.

use crate::errors;
use crate::field::{ByteOrder, Field};

/// `LC_SEGMENT` — 32-bit segment command.
pub const LC_SEGMENT: u32 = 0x1;
/// `LC_SYMTAB` — symbol table and string table location.
pub const LC_SYMTAB: u32 = 0x2;
/// `LC_UNIXTHREAD` — legacy entry point (register state).
pub const LC_UNIXTHREAD: u32 = 0x5;
/// `LC_DYSYMTAB` — dynamic symbol table indices.
pub const LC_DYSYMTAB: u32 = 0xb;
/// `LC_LOAD_DYLIB` — a dynamic library the image links against.
pub const LC_LOAD_DYLIB: u32 = 0xc;
/// `LC_ID_DYLIB` — install name of a dylib image.
pub const LC_ID_DYLIB: u32 = 0xd;
/// `LC_LOAD_DYLINKER` — dynamic linker path (`/usr/lib/dyld`).
pub const LC_LOAD_DYLINKER: u32 = 0xe;
/// `LC_SEGMENT_64` — 64-bit segment command.
pub const LC_SEGMENT_64: u32 = 0x19;
/// `LC_UUID` — 128-bit image identifier.
pub const LC_UUID: u32 = 0x1b;
/// `LC_RPATH` — runtime search path.
pub const LC_RPATH: u32 = 0x1c;
/// `LC_CODE_SIGNATURE` — code signing blob location (`linkedit_data`).
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
/// `LC_FUNCTION_STARTS` — compressed function start addresses (`linkedit_data`).
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// `LC_DATA_IN_CODE` — data-in-code entries (`linkedit_data`).
pub const LC_DATA_IN_CODE: u32 = 0x29;
/// `LC_DYLD_EXPORTS_TRIE` — export trie blob (`linkedit_data`).
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x80000033;
/// `LC_LOAD_WEAK_DYLIB` — weakly linked dylib.
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x80000018;
/// `LC_REEXPORT_DYLIB` — re-exported dylib.
pub const LC_REEXPORT_DYLIB: u32 = 0x8000001f;
/// `LC_LAZY_LOAD_DYLIB` — lazily loaded dylib.
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// `LC_DYLD_INFO` — compressed dyld information.
pub const LC_DYLD_INFO: u32 = 0x22;
/// `LC_DYLD_INFO_ONLY` — compressed dyld information (only form present).
pub const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
/// `LC_MAIN` — entry point offset for modern binaries.
pub const LC_MAIN: u32 = 0x80000028;
/// `LC_SOURCE_VERSION` — source version.
pub const LC_SOURCE_VERSION: u32 = 0x2a;
/// `LC_VERSION_MIN_MACOSX` — minimum macOS version.
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
/// `LC_VERSION_MIN_IPHONEOS` — minimum iOS version.
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
/// `LC_BUILD_VERSION` — build/platform version.
pub const LC_BUILD_VERSION: u32 = 0x32;
/// `LC_LINKER_OPTION` — linker command-line options embedded in the image.
pub const LC_LINKER_OPTION: u32 = 0x2d;
/// `LC_LINKER_OPTIMIZATION_HINT` — linker optimization hints.
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
/// `LC_VERSION_MIN_TVOS` — minimum tvOS version.
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
/// `LC_VERSION_MIN_WATCHOS` — minimum watchOS version.
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
/// `LC_FILESET_ENTRY` — fileset entry (iOS app extensions).
pub const LC_FILESET_ENTRY: u32 = 0x35;

/// Bit set on load command values whose payload dyld must understand to load the image.
pub const LC_REQ_DYLD: u32 = 0x80000000;

/// Load command header (`cmd` + `cmdsize`).
#[derive(Debug)]
pub struct LoadCommand {
    /// Load command type (`LC_*`).
    pub cmd: Field<u32>,
    /// Total size of this command including this header.
    pub cmdsize: Field<u32>,
}

/// `symtab_command` — symbol table and string table location.
#[derive(Debug)]
pub struct SymtabCommand {
    /// File offset of the `nlist` array.
    pub symoff: Field<u32>,
    /// Number of symbol entries.
    pub nsyms: Field<u32>,
    /// File offset of the string table.
    pub stroff: Field<u32>,
    /// Size in bytes of the string table.
    pub strsize: Field<u32>,
}

/// `dysymtab_command` — dynamic symbol table indices (subset of common fields).
#[derive(Debug)]
pub struct DysymtabCommand {
    /// Index of the first local symbol.
    pub ilocalsym: Field<u32>,
    /// Number of local symbols.
    pub nlocalsym: Field<u32>,
    /// Index of the first externally defined symbol.
    pub iextdefsym: Field<u32>,
    /// Number of externally defined symbols.
    pub nextdefsym: Field<u32>,
    /// Index of the first undefined symbol.
    pub iundefsym: Field<u32>,
    /// Number of undefined symbols.
    pub nundefsym: Field<u32>,
}

/// `dyld_info_command` — compressed rebase/bind/export blobs.
#[derive(Debug)]
pub struct DyldInfoCommand {
    pub rebase_off: Field<u32>,
    pub rebase_size: Field<u32>,
    pub bind_off: Field<u32>,
    pub bind_size: Field<u32>,
    pub weak_bind_off: Field<u32>,
    pub weak_bind_size: Field<u32>,
    pub lazy_bind_off: Field<u32>,
    pub lazy_bind_size: Field<u32>,
    pub export_off: Field<u32>,
    pub export_size: Field<u32>,
}

/// `entry_point_command` (`LC_MAIN`) — entry file offset and initial stack size.
#[derive(Debug)]
pub struct MainCommand {
    /// File (`__TEXT`) offset of the entry point.
    pub entryoff: Field<u64>,
    /// Initial stack size, or `0`.
    pub stacksize: Field<u64>,
}

/// `dylib_command` (`LC_LOAD_DYLIB` and friends) — a linked dynamic library.
#[derive(Debug)]
pub struct DylibCommand {
    /// Offset of the path string relative to the command start.
    pub name_offset: Field<u32>,
    /// Library build timestamp.
    pub timestamp: Field<u32>,
    /// Current version (`X.Y.Z` packed in 32 bits).
    pub current_version: Field<u32>,
    /// Compatibility version.
    pub compatibility_version: Field<u32>,
    /// Resolved library path.
    pub name: String,
}

/// `dylinker_command` / `rpath_command` — a single embedded path string.
#[derive(Debug)]
pub struct StrCommand {
    /// Offset of the string relative to the command start.
    pub str_offset: Field<u32>,
    /// Resolved string.
    pub name: String,
}

/// `uuid_command` — 128-bit image identifier.
#[derive(Debug)]
pub struct UuidCommand {
    /// Raw 16-byte UUID.
    pub uuid: [u8; 16],
}

/// `linkedit_data_command` — `(dataoff, datasize)` blob inside `__LINKEDIT`.
#[derive(Debug)]
pub struct LinkeditDataCommand {
    /// File offset of the blob.
    pub dataoff: Field<u32>,
    /// Size in bytes of the blob.
    pub datasize: Field<u32>,
}

/// `build_version_command` (`LC_BUILD_VERSION`).
#[derive(Debug)]
pub struct BuildVersionCommand {
    /// Target platform (`PLATFORM_*`).
    pub platform: Field<u32>,
    /// Minimum OS version (packed `X.Y.Z`).
    pub minos: Field<u32>,
    /// SDK version (packed `X.Y.Z`).
    pub sdk: Field<u32>,
    /// Number of `build_tool_version` records following this command.
    pub ntools: Field<u32>,
}

/// One `build_tool_version` record nested in [`BuildVersionCommand`].
#[derive(Debug)]
pub struct BuildToolVersion {
    /// Tool identifier (`TOOL_*`).
    pub tool: Field<u32>,
    /// Tool version (packed `X.Y.Z`).
    pub version: Field<u32>,
}

/// `source_version_command` (`LC_SOURCE_VERSION`).
#[derive(Debug)]
pub struct SourceVersionCommand {
    /// Source version (packed components in 64 bits).
    pub version: Field<u64>,
}

/// `version_min_command` (`LC_VERSION_MIN_*`).
#[derive(Debug)]
pub struct VersionMinCommand {
    /// Minimum OS version (packed `X.Y.Z`).
    pub version: Field<u32>,
    /// SDK version (packed `X.Y.Z`).
    pub sdk: Field<u32>,
}

/// `thread_command` (`LC_UNIXTHREAD`) — legacy entry point via CPU register state.
#[derive(Debug)]
pub struct UnixThreadCommand {
    /// CPU-specific thread-state flavor.
    pub flavor: Field<u32>,
    /// Number of `uint32_t` words in the thread state.
    pub count: Field<u32>,
    /// Absolute file offset of the thread-state blob.
    pub state_offset: usize,
    /// Raw thread-state bytes (`count * 4`).
    pub state: Vec<u8>,
}

/// `linker_option_command` (`LC_LINKER_OPTION`).
#[derive(Debug)]
pub struct LinkerOptionCommand {
    /// Number of NUL-terminated option strings.
    pub count: Field<u32>,
    /// Resolved option strings.
    pub options: Vec<String>,
}

/// `linker_optimization_hint_command` (`LC_LINKER_OPTIMIZATION_HINT`).
#[derive(Debug)]
pub struct LinkerOptimizationHintCommand {
    /// Number of hints.
    pub count: Field<u32>,
    /// Total size in bytes of the hint records.
    pub size: Field<u32>,
}

/// `fileset_entry_command` (`LC_FILESET_ENTRY`).
#[derive(Debug)]
pub struct FilesetEntryCommand {
    /// Virtual address of the entry Mach-O.
    pub vmaddr: Field<u64>,
    /// File offset of the entry Mach-O.
    pub fileoff: Field<u64>,
    /// Offset of the entry identifier string relative to the command start.
    pub entry_id_offset: Field<u32>,
    /// Resolved entry identifier (e.g. `com.apple.watchkit`).
    pub entry_id: String,
}

/// Typed view of a load command payload for the kinds HexSpell models.
#[derive(Debug)]
pub enum TypedCommand {
    Symtab(SymtabCommand),
    Dysymtab(DysymtabCommand),
    DyldInfo(DyldInfoCommand),
    Main(MainCommand),
    Dylib(DylibCommand),
    Dylinker(StrCommand),
    Rpath(StrCommand),
    Uuid(UuidCommand),
    LinkeditData(LinkeditDataCommand),
    BuildVersion(BuildVersionCommand),
    SourceVersion(SourceVersionCommand),
    VersionMin(VersionMinCommand),
    UnixThread(UnixThreadCommand),
    LinkerOption(LinkerOptionCommand),
    LinkerOptimizationHint(LinkerOptimizationHintCommand),
    FilesetEntry(FilesetEntryCommand),
}

impl LoadCommand {
    /// Absolute file offset of this command header.
    pub fn offset(&self) -> usize {
        self.cmd.offset
    }

    /// Parses the typed payload for this command, if HexSpell models its kind.
    ///
    /// Returns `Ok(None)` for commands without a typed view (e.g. segments, which are exposed via
    /// [`crate::macho::segment::SegmentEntry`]).
    pub fn typed(
        &self,
        buffer: &[u8],
        order: ByteOrder,
    ) -> Result<Option<TypedCommand>, errors::FileParseError> {
        let off = self.cmd.offset;
        let size = self.cmdsize.value as usize;
        let read_u32 = |rel: usize| order.read_u32(buffer, off + rel);
        let read_u64 = |rel: usize| order.read_u64(buffer, off + rel);

        let typed = match self.cmd.value {
            LC_SYMTAB => TypedCommand::Symtab(SymtabCommand {
                symoff: Field::new(read_u32(8)?, off + 8, 4),
                nsyms: Field::new(read_u32(12)?, off + 12, 4),
                stroff: Field::new(read_u32(16)?, off + 16, 4),
                strsize: Field::new(read_u32(20)?, off + 20, 4),
            }),
            LC_DYSYMTAB => TypedCommand::Dysymtab(DysymtabCommand {
                ilocalsym: Field::new(read_u32(8)?, off + 8, 4),
                nlocalsym: Field::new(read_u32(12)?, off + 12, 4),
                iextdefsym: Field::new(read_u32(16)?, off + 16, 4),
                nextdefsym: Field::new(read_u32(20)?, off + 20, 4),
                iundefsym: Field::new(read_u32(24)?, off + 24, 4),
                nundefsym: Field::new(read_u32(28)?, off + 28, 4),
            }),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => TypedCommand::DyldInfo(DyldInfoCommand {
                rebase_off: Field::new(read_u32(8)?, off + 8, 4),
                rebase_size: Field::new(read_u32(12)?, off + 12, 4),
                bind_off: Field::new(read_u32(16)?, off + 16, 4),
                bind_size: Field::new(read_u32(20)?, off + 20, 4),
                weak_bind_off: Field::new(read_u32(24)?, off + 24, 4),
                weak_bind_size: Field::new(read_u32(28)?, off + 28, 4),
                lazy_bind_off: Field::new(read_u32(32)?, off + 32, 4),
                lazy_bind_size: Field::new(read_u32(36)?, off + 36, 4),
                export_off: Field::new(read_u32(40)?, off + 40, 4),
                export_size: Field::new(read_u32(44)?, off + 44, 4),
            }),
            LC_MAIN => TypedCommand::Main(MainCommand {
                entryoff: Field::new(read_u64(8)?, off + 8, 8),
                stacksize: Field::new(read_u64(16)?, off + 16, 8),
            }),
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
            | LC_LAZY_LOAD_DYLIB => {
                let name_offset = read_u32(8)?;
                let name = read_lc_string(buffer, off, size, name_offset as usize)?;
                TypedCommand::Dylib(DylibCommand {
                    name_offset: Field::new(name_offset, off + 8, 4),
                    timestamp: Field::new(read_u32(12)?, off + 12, 4),
                    current_version: Field::new(read_u32(16)?, off + 16, 4),
                    compatibility_version: Field::new(read_u32(20)?, off + 20, 4),
                    name,
                })
            }
            LC_LOAD_DYLINKER => {
                let str_offset = read_u32(8)?;
                let name = read_lc_string(buffer, off, size, str_offset as usize)?;
                TypedCommand::Dylinker(StrCommand {
                    str_offset: Field::new(str_offset, off + 8, 4),
                    name,
                })
            }
            LC_RPATH => {
                let str_offset = read_u32(8)?;
                let name = read_lc_string(buffer, off, size, str_offset as usize)?;
                TypedCommand::Rpath(StrCommand {
                    str_offset: Field::new(str_offset, off + 8, 4),
                    name,
                })
            }
            LC_UUID => {
                let bytes = buffer
                    .get(off + 8..off + 24)
                    .ok_or(errors::FileParseError::BufferOverflow)?;
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(bytes);
                TypedCommand::Uuid(UuidCommand { uuid })
            }
            LC_CODE_SIGNATURE | LC_FUNCTION_STARTS | LC_DATA_IN_CODE | LC_DYLD_EXPORTS_TRIE => {
                TypedCommand::LinkeditData(LinkeditDataCommand {
                    dataoff: Field::new(read_u32(8)?, off + 8, 4),
                    datasize: Field::new(read_u32(12)?, off + 12, 4),
                })
            }
            LC_BUILD_VERSION => TypedCommand::BuildVersion(BuildVersionCommand {
                platform: Field::new(read_u32(8)?, off + 8, 4),
                minos: Field::new(read_u32(12)?, off + 12, 4),
                sdk: Field::new(read_u32(16)?, off + 16, 4),
                ntools: Field::new(read_u32(20)?, off + 20, 4),
            }),
            LC_SOURCE_VERSION => TypedCommand::SourceVersion(SourceVersionCommand {
                version: Field::new(read_u64(8)?, off + 8, 8),
            }),
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => TypedCommand::VersionMin(VersionMinCommand {
                version: Field::new(read_u32(8)?, off + 8, 4),
                sdk: Field::new(read_u32(12)?, off + 12, 4),
            }),
            LC_UNIXTHREAD => {
                let flavor = read_u32(8)?;
                let count = read_u32(12)?;
                let state_off = off + 16;
                let state_len = count as usize * 4;
                let state = buffer
                    .get(state_off..state_off + state_len)
                    .ok_or(errors::FileParseError::BufferOverflow)?
                    .to_vec();
                TypedCommand::UnixThread(UnixThreadCommand {
                    flavor: Field::new(flavor, off + 8, 4),
                    count: Field::new(count, off + 12, 4),
                    state_offset: state_off,
                    state,
                })
            }
            LC_LINKER_OPTION => {
                let count = read_u32(8)?;
                let mut options = Vec::new();
                let mut str_pos = off + 12;
                let cmd_end = off + size;
                for _ in 0..count {
                    if str_pos >= cmd_end {
                        return Err(errors::FileParseError::BufferOverflow);
                    }
                    let slice = buffer
                        .get(str_pos..cmd_end)
                        .ok_or(errors::FileParseError::BufferOverflow)?;
                    let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                    let opt = String::from_utf8_lossy(&slice[..stop]).into_owned();
                    str_pos += stop + 1;
                    options.push(opt);
                }
                TypedCommand::LinkerOption(LinkerOptionCommand {
                    count: Field::new(count, off + 8, 4),
                    options,
                })
            }
            LC_LINKER_OPTIMIZATION_HINT => {
                TypedCommand::LinkerOptimizationHint(LinkerOptimizationHintCommand {
                    count: Field::new(read_u32(8)?, off + 8, 4),
                    size: Field::new(read_u32(12)?, off + 12, 4),
                })
            }
            LC_FILESET_ENTRY => {
                let entry_id_off = read_u32(24)?;
                let entry_id = read_lc_string(buffer, off, size, entry_id_off as usize)?;
                TypedCommand::FilesetEntry(FilesetEntryCommand {
                    vmaddr: Field::new(read_u64(8)?, off + 8, 8),
                    fileoff: Field::new(read_u64(16)?, off + 16, 8),
                    entry_id_offset: Field::new(entry_id_off, off + 24, 4),
                    entry_id,
                })
            }
            _ => return Ok(None),
        };

        Ok(Some(typed))
    }

    pub(crate) fn parse_load_commands(
        buffer: &[u8],
        offset: usize,
        ncmds: u32,
        order: ByteOrder,
    ) -> Result<Vec<Self>, errors::FileParseError> {
        let mut commands = Vec::new();
        let mut current_offset = offset;

        for _ in 0..ncmds {
            if buffer.len() < current_offset + 8 {
                return Err(errors::FileParseError::BufferOverflow);
            }

            let cmd = Field::new(order.read_u32(buffer, current_offset)?, current_offset, 4);
            let cmdsize = Field::new(
                order.read_u32(buffer, current_offset + 4)?,
                current_offset + 4,
                4,
            );

            if cmdsize.value == 0 {
                return Err(errors::FileParseError::InvalidFileFormat);
            }

            commands.push(LoadCommand {
                cmd,
                cmdsize: cmdsize.clone(),
            });
            current_offset += cmdsize.value as usize;
        }

        Ok(commands)
    }
}

/// Parses `ntools` [`BuildToolVersion`] records following a [`BuildVersionCommand`].
pub fn parse_build_tools(
    buffer: &[u8],
    cmd: &BuildVersionCommand,
    cmd_offset: usize,
    order: ByteOrder,
) -> Result<Vec<BuildToolVersion>, errors::FileParseError> {
    let ntools = cmd.ntools.value as usize;
    let mut out = Vec::with_capacity(ntools);
    let mut off = cmd_offset + 24;
    for _ in 0..ntools {
        if buffer.len() < off + 8 {
            return Err(errors::FileParseError::BufferOverflow);
        }
        let order = order;
        out.push(BuildToolVersion {
            tool: Field::new(order.read_u32(buffer, off)?, off, 4),
            version: Field::new(order.read_u32(buffer, off + 4)?, off + 4, 4),
        });
        off += 8;
    }
    Ok(out)
}

/// Reads a NUL-terminated (or command-end-terminated) string embedded in a load command.
fn read_lc_string(
    buffer: &[u8],
    cmd_offset: usize,
    cmd_size: usize,
    str_offset: usize,
) -> Result<String, errors::FileParseError> {
    if str_offset >= cmd_size {
        return Err(errors::FileParseError::InvalidFileFormat);
    }
    let start = cmd_offset + str_offset;
    let end = cmd_offset + cmd_size;
    let slice = buffer
        .get(start..end)
        .ok_or(errors::FileParseError::BufferOverflow)?;
    let stop = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..stop]).into_owned())
}
