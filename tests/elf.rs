/// HexSpell ELF
/// ====================================
/// File for testing ELF functionalities
///
/// REFERENCES
/// -----------
/// 1. ELF Structure       =>  https://wiki.osdev.org/ELF
/// 2. ELF Viewer Online   =>  http://www.sunshine2k.de/coding/javascript/onlineelfviewer/onlineelfviewer.html
///
use std::fs;
use toml::Value;

use hexspell::elf; // <-- Testing module
use hexspell::errors::FileParseError;

/// ==========================================
/// Testing reading and parsing in an ELF file
/// ==========================================
#[test]
fn test_elf_parse() {
    let toml_contents: String =
        fs::read_to_string("tests/tests.toml").expect("Failed to read tests.toml");
    let data: Value = toml_contents
        .parse::<Value>()
        .expect("Failed to parse TOML");

    // ELF FILES
    if let Some(elf) = data.get("elf").and_then(|v| v.as_table()) {
        for (key, value) in elf {
            let file_extension: &str = value
                .get("file_extension")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut file_name: String = format!("tests/samples/{}", key);
            if !file_extension.is_empty() {
                file_name += &format!(".{}", file_extension);
            }
            let elf: elf::ELF = elf::ELF::from_file(&file_name).expect("Error parsing ELF file");

            let e_version = value
                .get("e_version")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_entry = value
                .get("e_entry")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_phoff = value
                .get("e_phoff")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_shoff = value
                .get("e_shoff")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_flags = value
                .get("e_flags")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_ehsize = value
                .get("e_ehsize")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_phentsize = value
                .get("e_phentsize")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_phnum = value
                .get("e_phnum")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_shentsize = value
                .get("e_shentsize")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_shnum = value
                .get("e_shnum")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let e_shstrndx = value
                .get("e_shstrndx")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_type = value
                .get("p1_p_type")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_flags = value
                .get("p1_p_flags")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_offset = value
                .get("p1_p_offset")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_vaddr = value
                .get("p1_p_vaddr")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_paddr = value
                .get("p1_p_paddr")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_filesz = value
                .get("p1_p_filesz")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_memsz = value
                .get("p1_p_memsz")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let p1_p_align = value
                .get("p1_p_align")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_type = value
                .get("sh1_sh_type")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_flags = value
                .get("sh1_sh_flags")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_addr = value
                .get("sh1_sh_addr")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_offset = value
                .get("sh1_sh_offset")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_size = value
                .get("sh1_sh_size")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_link = value
                .get("sh1_sh_link")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_info = value
                .get("sh1_sh_info")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_addralign = value
                .get("sh1_sh_addralign")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            let sh1_sh_entsize = value
                .get("sh1_sh_entsize")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            assert_eq!(
                elf.header.version.value, e_version,
                "header.version doesnt match"
            );
            assert_eq!(elf.header.entry.value, e_entry, "header.entry doesnt match");
            assert_eq!(
                elf.header.ph_off.value, e_phoff,
                "header.ph_off doesnt match"
            );
            assert_eq!(
                elf.header.sh_off.value, e_shoff,
                "header.hs_off doesnt match"
            );
            assert_eq!(elf.header.flags.value, e_flags, "header.flags doesnt match");
            assert_eq!(
                elf.header.eh_size.value, e_ehsize,
                "header.sh_size doesnt match"
            );
            assert_eq!(
                elf.header.ph_ent_size.value, e_phentsize,
                "header.ph_ent_size doesnt match"
            );
            assert_eq!(
                elf.header.ph_num.value, e_phnum,
                "header.ph_num doesnt match"
            );
            assert_eq!(
                elf.header.sh_ent_size.value, e_shentsize,
                "header.sh_ent_size doesnt match"
            );
            assert_eq!(
                elf.header.sh_num.value, e_shnum,
                "header.sh_num doesnt match"
            );
            assert_eq!(
                elf.header.sh_strndx.value, e_shstrndx,
                "header.sh_strndx doesnt match"
            );

            assert_eq!(
                elf.program_headers[0].p_type.value, p1_p_type,
                "program header 0.p_type doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_flags.value, p1_p_flags,
                "program header 0.p_flags doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_offset.value, p1_p_offset,
                "program header 0.p_offset doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_vaddr.value, p1_p_vaddr,
                "program header 0.p_vaddr doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_paddr.value, p1_p_paddr,
                "program header 0.p_paddr doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_filesz.value, p1_p_filesz,
                "program header 0.p_filesz doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_memsz.value, p1_p_memsz,
                "program header 0.p_memsz doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_align.value, p1_p_align,
                "program header 0.p_align doesn't match"
            );

            assert_eq!(
                elf.section_headers[0].sh_type.value, sh1_sh_type,
                "section header 0.sh_type doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_flags.value, sh1_sh_flags,
                "section header 0.sh_flags doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_addr.value, sh1_sh_addr,
                "section header 0.sh_addr doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_offset.value, sh1_sh_offset,
                "section header 0.sh_offset doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_size.value, sh1_sh_size,
                "section header 0.sh_size doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_link.value, sh1_sh_link,
                "section header 0.sh_link doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_info.value, sh1_sh_info,
                "section header 0.sh_info doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_addralign.value, sh1_sh_addralign,
                "section header 0.sh_addralign doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_entsize.value, sh1_sh_entsize,
                "section header 0.sh_entsize doesn't match"
            );
        }
    }
}

/// Parsing an insufficient ELF buffer should return BufferOverflow
#[test]
fn test_elf_invalid_buffer() {
    let buffer = vec![0u8; 10];
    let result = elf::ELF::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::BufferOverflow)));
}

/// Parsing a buffer with an invalid ELF magic should return InvalidFileFormat
#[test]
fn test_elf_invalid_magic() {
    let mut buffer = vec![0u8; 64];
    buffer[0..4].copy_from_slice(b"BAD!");
    let result = elf::ELF::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
}

/// Parsing a buffer with an unsupported endianness should return InvalidFileFormat
#[test]
fn test_elf_invalid_endianness() {
    let mut buffer = vec![0u8; 64];
    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[5] = 3; // Invalid endianness identifier
    let result = elf::ELF::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
}

/// Parsing a big-endian ELF buffer should succeed and read values correctly
#[test]
fn test_elf_big_endian_parse() {
    let mut buffer = vec![0u8; 64 + 56 + 64];

    // e_ident
    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[4] = 2; // ELFCLASS64
    buffer[5] = 2; // Big endian
    buffer[6] = 1; // ELF version

    // ELF header fields
    buffer[16..18].copy_from_slice(&2u16.to_be_bytes()); // e_type
    buffer[18..20].copy_from_slice(&0x003Eu16.to_be_bytes()); // e_machine
    buffer[20..24].copy_from_slice(&1u32.to_be_bytes()); // e_version
    buffer[24..32].copy_from_slice(&0x1122334455667788u64.to_be_bytes()); // e_entry
    buffer[32..40].copy_from_slice(&64u64.to_be_bytes()); // e_phoff
    buffer[40..48].copy_from_slice(&120u64.to_be_bytes()); // e_shoff
    buffer[48..52].copy_from_slice(&0u32.to_be_bytes()); // e_flags
    buffer[52..54].copy_from_slice(&64u16.to_be_bytes()); // e_ehsize
    buffer[54..56].copy_from_slice(&56u16.to_be_bytes()); // e_phentsize
    buffer[56..58].copy_from_slice(&1u16.to_be_bytes()); // e_phnum
    buffer[58..60].copy_from_slice(&64u16.to_be_bytes()); // e_shentsize
    buffer[60..62].copy_from_slice(&1u16.to_be_bytes()); // e_shnum
    buffer[62..64].copy_from_slice(&0u16.to_be_bytes()); // e_shstrndx

    // Program header at offset 64
    let ph = 64;
    buffer[ph..ph + 4].copy_from_slice(&1u32.to_be_bytes()); // p_type
    buffer[ph + 4..ph + 8].copy_from_slice(&5u32.to_be_bytes()); // p_flags
    buffer[ph + 8..ph + 16].copy_from_slice(&0x111u64.to_be_bytes()); // p_offset
    buffer[ph + 16..ph + 24].copy_from_slice(&0x222u64.to_be_bytes()); // p_vaddr
    buffer[ph + 24..ph + 32].copy_from_slice(&0x333u64.to_be_bytes()); // p_paddr
    buffer[ph + 32..ph + 40].copy_from_slice(&0x444u64.to_be_bytes()); // p_filesz
    buffer[ph + 40..ph + 48].copy_from_slice(&0x555u64.to_be_bytes()); // p_memsz
    buffer[ph + 48..ph + 56].copy_from_slice(&8u64.to_be_bytes()); // p_align

    // Section header at offset 120
    let sh = 120;
    buffer[sh..sh + 4].copy_from_slice(&1u32.to_be_bytes()); // sh_name
    buffer[sh + 4..sh + 8].copy_from_slice(&1u32.to_be_bytes()); // sh_type
    buffer[sh + 8..sh + 16].copy_from_slice(&0xAAAu64.to_be_bytes()); // sh_flags
    buffer[sh + 16..sh + 24].copy_from_slice(&0xBBBu64.to_be_bytes()); // sh_addr
    buffer[sh + 24..sh + 32].copy_from_slice(&184u64.to_be_bytes()); // sh_offset
    buffer[sh + 32..sh + 40].copy_from_slice(&0x10u64.to_be_bytes()); // sh_size
    buffer[sh + 40..sh + 44].copy_from_slice(&0u32.to_be_bytes()); // sh_link
    buffer[sh + 44..sh + 48].copy_from_slice(&0u32.to_be_bytes()); // sh_info
    buffer[sh + 48..sh + 56].copy_from_slice(&1u64.to_be_bytes()); // sh_addralign
    buffer[sh + 56..sh + 64].copy_from_slice(&0u64.to_be_bytes()); // sh_entsize

    let elf = elf::ELF::from_buffer(buffer).expect("Failed to parse big-endian ELF");

    assert!(matches!(
        elf.header.endianness,
        elf::header::Endianness::Big
    ));
    assert_eq!(elf.program_headers[0].p_type.value, 1);
    assert_eq!(elf.program_headers[0].p_offset.value, 0x111);
    assert_eq!(elf.section_headers[0].sh_flags.value, 0xAAA);
    assert_eq!(elf.section_headers[0].sh_offset.value, 184);
}
