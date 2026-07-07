/// HexSpell Mach-O
/// ====================================
/// File to perform test on Mach-O parse
///
/// REFERENCES
/// -----------
/// Mach-O Structure    =>  https://book.hacktricks.xyz/macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/universal-binaries-and-mach-o-format
/// Mach-O Viewer       =>  https://github.com/horsicq/XMachOViewer
///
use std::fs;
use toml::Value;

use hexspell::errors::FileParseError;
use hexspell::field::ByteOrder;
use hexspell::macho; // <-- Testing module

/// ============================================
/// Testing reading and parsing in a Mach-O file
/// ============================================
#[test]
fn test_macho_parse() {
    let toml_contents: String =
        fs::read_to_string("tests/tests.toml").expect("Failed to read tests.toml");
    let data: Value = toml::from_str(&toml_contents).expect("Failed to parse TOML");

    // MACHO FILES
    if let Some(elf) = data.get("macho").and_then(|v| v.as_table()) {
        for (key, value) in elf {
            let file_extension: &str = value
                .get("file_extension")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut file_name: String = format!("tests/samples/{}", key);
            if !file_extension.is_empty() {
                file_name += &format!(".{}", file_extension);
            }

            // Getting real values from test.toml
            let macho_file: macho::MachO =
                macho::MachO::from_file(&file_name).expect("Error parsing MachO file");

            let magic = value
                .get("magic")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let cputype = value
                .get("cputype")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let cpusubtype = value
                .get("cpusubtype")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let filetype = value
                .get("filetype")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let ncmds = value
                .get("ncmds")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sizeofcmds = value
                .get("sizeofcmds")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let flags = value
                .get("flags")
                .and_then(|v| v.as_str())
                .map(|s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            // Testing parse params result
            assert_eq!(
                macho_file.header.magic.value, magic,
                "macho_file.header.magic doesnt match"
            );
            assert_eq!(
                macho_file.header.cpu_type.value, cputype,
                "macho_file.header.cpu_type doesnt match"
            );
            assert_eq!(
                macho_file.header.cpu_subtype.value, cpusubtype,
                "macho_file.header.cpu_subtype doesnt match"
            );
            assert_eq!(
                macho_file.header.file_type.value, filetype,
                "macho_file.header.file_type doesnt match"
            );
            assert_eq!(
                macho_file.header.ncmds.value, ncmds,
                "macho_file.header.ncmds doesnt match"
            );
            assert_eq!(
                macho_file.header.sizeofcmds.value, sizeofcmds,
                "macho_file.header.sizeofcmds doesnt match"
            );
            assert_eq!(
                macho_file.header.flags.value, flags,
                "macho_file.header.flags doesnt match"
            );
        }
    }
}

/// 32-bit Mach-O must not expose a reserved field at offset 28
#[test]
fn test_macho_32bit_reserved_is_none() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    assert!(
        macho_file.header.reserved.is_none(),
        "32-bit Mach-O must not have a reserved field"
    );
}

/// 64-bit Mach-O must expose reserved at offset 28
#[test]
fn test_macho_64bit_reserved_is_some() {
    let buffer = vec![
        0xCF, 0xFA, 0xED, 0xFE, // magic (64-bit LE)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
        0x42, 0x00, 0x00, 0x00, // reserved
    ];
    let macho_file = macho::MachO::from_buffer(buffer.clone()).expect("64-bit parse failed");
    let reserved = macho_file
        .header
        .reserved
        .as_ref()
        .expect("64-bit Mach-O must have reserved");
    assert_eq!(reserved.value, 0x42);
    assert_eq!(reserved.offset, 28);
}

/// Parsing a buffer without a valid Mach-O magic number should fail
#[test]
fn test_macho_invalid_buffer() {
    let buffer = vec![0u8; 4];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
}

/// Parsing a little-endian Mach-O buffer should succeed
#[test]
fn test_macho_parse_little_endian() {
    let buffer = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let macho_file = macho::MachO::from_buffer(buffer).expect("Error parsing little-endian MachO");
    assert_eq!(macho_file.byte_order(), ByteOrder::Little);
    assert_eq!(macho_file.header.magic.value, 0xFEEDFACE);
    assert_eq!(macho_file.header.cpu_type.value, 0x00000007);
    assert_eq!(macho_file.header.cpu_subtype.value, 0x00000003);
}

/// Missing load commands in a little-endian Mach-O should error
#[test]
fn test_macho_little_endian_missing_load_commands() {
    let buffer = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x01, 0x00, 0x00, 0x00, // ncmds = 1
        0x08, 0x00, 0x00, 0x00, // sizeofcmds = 8
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::BufferOverflow)));
}

/// Parsing a big-endian Mach-O buffer should succeed
#[test]
fn test_macho_parse_big_endian() {
    let buffer = vec![
        0xFE, 0xED, 0xFA, 0xCE, // magic (big-endian)
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
        0x00, 0x00, 0x00, 0x02, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let macho_file = macho::MachO::from_buffer(buffer).expect("Error parsing big-endian MachO");
    assert_eq!(macho_file.byte_order(), ByteOrder::Big);
    assert_eq!(macho_file.header.magic.value, 0xFEEDFACE);
    assert_eq!(macho_file.header.cpu_type.value, 0x00000007);
    assert_eq!(macho_file.header.cpu_subtype.value, 0x00000003);
}

/// Missing load commands in a big-endian Mach-O should error
#[test]
fn test_macho_big_endian_missing_load_commands() {
    let buffer = vec![
        0xFE, 0xED, 0xFA, 0xCE, // magic (big-endian)
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
        0x00, 0x00, 0x00, 0x02, // filetype
        0x00, 0x00, 0x00, 0x01, // ncmds = 1
        0x00, 0x00, 0x00, 0x08, // sizeofcmds = 8
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::BufferOverflow)));
}

/// Parsing a FAT Mach-O buffer should succeed
#[test]
fn test_macho_parse_fat() {
    let inner = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x00, 0x00, 0x00, 0x00, // ncmds
        0x00, 0x00, 0x00, 0x00, // sizeofcmds
        0x00, 0x00, 0x00, 0x00, // flags
    ];
    let offset = 0x20u32;
    let size = inner.len() as u32;
    let mut buffer = vec![
        0xCA, 0xFE, 0xBA, 0xBE, // FAT magic
        0x00, 0x00, 0x00, 0x01, // nfat_arch
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
    ];
    buffer.extend_from_slice(&offset.to_be_bytes());
    buffer.extend_from_slice(&size.to_be_bytes());
    buffer.extend_from_slice(&0u32.to_be_bytes()); // align
    buffer.extend(vec![0u8; offset as usize - buffer.len()]);
    buffer.extend_from_slice(&inner);

    let macho_file = macho::MachO::from_buffer(buffer).expect("Error parsing FAT MachO");
    assert_eq!(macho_file.byte_order(), ByteOrder::Little);
    assert_eq!(macho_file.header.magic.value, 0xFEEDFACE);
}

/// Invalid offsets in a FAT Mach-O should error
#[test]
fn test_macho_fat_invalid_offset() {
    let mut buffer = vec![
        0xCA, 0xFE, 0xBA, 0xBE, // FAT magic
        0x00, 0x00, 0x00, 0x01, // nfat_arch
        0x00, 0x00, 0x00, 0x07, // cputype
        0x00, 0x00, 0x00, 0x03, // cpusubtype
    ];
    buffer.extend_from_slice(&0x40u32.to_be_bytes()); // offset beyond buffer
    buffer.extend_from_slice(&0x08u32.to_be_bytes()); // size
    buffer.extend_from_slice(&0u32.to_be_bytes()); // align

    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::BufferOverflow)));
}

/// Load command with cmdsize zero must not loop forever
#[test]
fn test_macho_cmdsize_zero_invalid() {
    let buffer = vec![
        0xCE, 0xFA, 0xED, 0xFE, // magic (little-endian 32-bit)
        0x07, 0x00, 0x00, 0x00, // cputype
        0x03, 0x00, 0x00, 0x00, // cpusubtype
        0x02, 0x00, 0x00, 0x00, // filetype
        0x01, 0x00, 0x00, 0x00, // ncmds = 1
        0x08, 0x00, 0x00, 0x00, // sizeofcmds = 8
        0x00, 0x00, 0x00, 0x00, // flags
        0x01, 0x00, 0x00, 0x00, // LC_SEGMENT cmd
        0x00, 0x00, 0x00, 0x00, // cmdsize = 0
    ];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
}

/// 32-bit LC_SEGMENT must use u32 layout for segment fields
#[test]
fn test_macho_segment_32bit_vmaddr() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    assert!(!macho_file.segments.is_empty());
    assert_eq!(macho_file.segments[0].name(), "__PAGEZERO");
    assert_eq!(macho_file.segments[0].vmaddr(), 0);
    assert_eq!(macho_file.segments[0].vmaddr_size(), 4);
}

/// Ensure writing a Mach-O file to disk succeeds and preserves contents
#[test]
fn test_macho_write_file() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let tmp_path = std::env::temp_dir().join("macho_write_test");
    macho_file
        .write_file(tmp_path.to_str().unwrap())
        .expect("Error writing MachO to disk");

    let original = std::fs::read("tests/samples/machO-OSX-x86-ls")
        .expect("[!] Failed to read original MachO file");
    let written = std::fs::read(&tmp_path).expect("[!] Failed to read written MachO file");
    assert_eq!(original, written);

    std::fs::remove_file(tmp_path).expect("[!] Failed to remove written MachO file");
}

/// Writing a Mach-O file to a non-existent directory should fail
#[test]
fn test_macho_write_file_fail() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let invalid_path = std::env::temp_dir()
        .join("nonexistent_dir")
        .join("macho.bin");
    let result = macho_file.write_file(invalid_path.to_str().unwrap());
    assert!(result.is_err());
}

/// Nested section records must be parsed from segment load commands (32-bit sample)
#[test]
fn test_macho_sections_parsed() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    // __TEXT has 5 sections, __DATA has 7 → 12 total.
    assert_eq!(macho_file.sections.len(), 12);
    let first = &macho_file.sections[0];
    assert_eq!(first.name(), "__text");
    assert_eq!(first.segment_name(), "__TEXT");
    assert_eq!(first.addr(), 5896);
    assert_eq!(first.size(), 15988);
    assert_eq!(first.offset(), 1800);
}

/// LC_SYMTAB symbols must resolve their names against the string table
#[test]
fn test_macho_symbols_parsed() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let symbols = macho_file
        .symbols()
        .expect("symbol parse")
        .expect("sample has LC_SYMTAB");
    assert_eq!(symbols.symbols.len(), 86);
    // At least one symbol name should resolve to a non-empty C string.
    assert!(symbols.symbols.iter().any(|s| !s.name.is_empty()));
}

/// Linked dylibs must be listed with their resolved paths
#[test]
fn test_macho_linked_dylibs() {
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let dylibs = macho_file.linked_dylibs().expect("dylib parse");
    assert_eq!(dylibs.len(), 3);
    assert!(dylibs.iter().any(|d| d == "/usr/lib/libSystem.B.dylib"));
    assert!(dylibs.iter().any(|d| d.contains("libncurses")));
}

/// Typed command iteration must expose the modeled load commands
#[test]
fn test_macho_typed_commands() {
    use macho::load_command::TypedCommand;
    let macho_file = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls")
        .expect("Error parsing MachO file");
    let typed = macho_file.typed_commands().expect("typed commands");

    let has_symtab = typed.iter().any(|c| matches!(c, TypedCommand::Symtab(_)));
    let has_dyld_info = typed.iter().any(|c| matches!(c, TypedCommand::DyldInfo(_)));
    let has_dylinker = typed.iter().any(|c| matches!(c, TypedCommand::Dylinker(_)));
    assert!(has_symtab, "expected an LC_SYMTAB typed command");
    assert!(has_dyld_info, "expected an LC_DYLD_INFO typed command");
    assert!(has_dylinker, "expected an LC_LOAD_DYLINKER typed command");

    for c in &typed {
        if let TypedCommand::Dylinker(s) = c {
            assert_eq!(s.name, "/usr/lib/dyld");
        }
    }
}

/// A thin Mach-O reports no FAT architectures
#[test]
fn test_macho_fat_architectures_thin() {
    let arches =
        macho::MachO::fat_architectures("tests/samples/machO-OSX-x86-ls").expect("fat query");
    assert!(arches.is_empty());
}

/// Typed section parsing for a hand-built 64-bit segment with one section_64
#[test]
fn test_macho_section_64_parsed() {
    let mut buffer = vec![0u8; 256];
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes()); // 64-bit magic
    buffer[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
    buffer[20..24].copy_from_slice(&(72u32 + 80u32).to_le_bytes()); // sizeofcmds
    let seg = 32usize;
    buffer[seg..seg + 4].copy_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
    buffer[seg + 4..seg + 8].copy_from_slice(&(72u32 + 80u32).to_le_bytes()); // cmdsize
    buffer[seg + 8..seg + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes()); // nsects = 1

    let sect = seg + 72;
    buffer[sect..sect + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    buffer[sect + 16..sect + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[sect + 32..sect + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // addr
    buffer[sect + 40..sect + 48].copy_from_slice(&0x40u64.to_le_bytes()); // size
    buffer[sect + 48..sect + 52].copy_from_slice(&0x200u32.to_le_bytes()); // offset

    let macho = macho::MachO::from_buffer(buffer).expect("parse macho");
    assert_eq!(macho.sections.len(), 1);
    assert_eq!(macho.sections[0].name(), "__text");
    assert_eq!(macho.sections[0].addr(), 0x1000);
    assert_eq!(macho.sections[0].size(), 0x40);
    assert_eq!(macho.sections[0].offset(), 0x200);
}

/// insert_segment appends LC when load-command region has room
#[test]
fn test_macho_insert_segment() {
    let mut buffer = vec![0u8; 256];
    // 64-bit Mach-O header (32 bytes)
    buffer[0..4].copy_from_slice(&0xFEEDFACFu32.to_le_bytes());
    buffer[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
    buffer[20..24].copy_from_slice(&72u32.to_le_bytes()); // sizeofcmds (one LC_SEGMENT_64)
                                                          // LC_SEGMENT_64 at offset 32, cmdsize 72, fileoff 200
    buffer[32..36].copy_from_slice(&0x19u32.to_le_bytes());
    buffer[36..40].copy_from_slice(&72u32.to_le_bytes());
    buffer[32 + 8..32 + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[32 + 40..32 + 48].copy_from_slice(&200u64.to_le_bytes()); // fileoff

    let mut macho = macho::MachO::from_buffer(buffer).expect("parse macho");
    assert_eq!(macho.segments.len(), 1);

    macho
        .insert_segment(macho::segment::NewSegment {
            name: "__DATA.inj".to_string(),
            data: vec![0x41, 0x42],
            initprot: macho::segment::prot::READ | macho::segment::prot::WRITE,
            maxprot: macho::segment::prot::READ | macho::segment::prot::WRITE,
        })
        .expect("insert_segment");

    assert_eq!(macho.segments.len(), 2);
    assert_eq!(macho.segments[1].name(), "__DATA.inj");
    assert_eq!(macho.segments[1].filesize(), 2);
}
