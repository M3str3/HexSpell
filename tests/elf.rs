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
    let data: Value = toml::from_str(&toml_contents).expect("Failed to parse TOML");

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
                elf.program_headers[0].p_type(),
                p1_p_type,
                "program header 0.p_type doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_flags(),
                p1_p_flags,
                "program header 0.p_flags doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_offset(),
                p1_p_offset,
                "program header 0.p_offset doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_vaddr(),
                p1_p_vaddr,
                "program header 0.p_vaddr doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_paddr(),
                p1_p_paddr,
                "program header 0.p_paddr doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_filesz(),
                p1_p_filesz,
                "program header 0.p_filesz doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_memsz(),
                p1_p_memsz,
                "program header 0.p_memsz doesn't match"
            );
            assert_eq!(
                elf.program_headers[0].p_align(),
                p1_p_align,
                "program header 0.p_align doesn't match"
            );

            assert_eq!(
                elf.section_headers[0].sh_type(),
                sh1_sh_type,
                "section header 0.sh_type doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_flags(),
                sh1_sh_flags,
                "section header 0.sh_flags doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_addr(),
                sh1_sh_addr,
                "section header 0.sh_addr doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_offset(),
                sh1_sh_offset,
                "section header 0.sh_offset doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_size(),
                sh1_sh_size,
                "section header 0.sh_size doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_link(),
                sh1_sh_link,
                "section header 0.sh_link doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_info(),
                sh1_sh_info,
                "section header 0.sh_info doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_addralign(),
                sh1_sh_addralign,
                "section header 0.sh_addralign doesn't match"
            );
            assert_eq!(
                elf.section_headers[0].sh_entsize(),
                sh1_sh_entsize,
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

    assert_eq!(elf.byte_order().unwrap(), hexspell::field::ByteOrder::Big);
    assert_eq!(elf.program_headers[0].p_type(), 1);
    assert_eq!(elf.program_headers[0].p_offset(), 0x111);
    assert_eq!(elf.section_headers[0].sh_flags(), 0xAAA);
    assert_eq!(elf.section_headers[0].sh_offset(), 184);
}

/// Big-endian ELF entry point can be updated and re-parsed correctly
#[test]
fn test_elf_big_endian_entry_update() {
    let mut buffer = vec![0u8; 64 + 56 + 64];

    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[4] = 2;
    buffer[5] = 2;
    buffer[6] = 1;

    buffer[16..18].copy_from_slice(&2u16.to_be_bytes());
    buffer[18..20].copy_from_slice(&0x003Eu16.to_be_bytes());
    buffer[20..24].copy_from_slice(&1u32.to_be_bytes());
    buffer[24..32].copy_from_slice(&0x1122334455667788u64.to_be_bytes());
    buffer[32..40].copy_from_slice(&64u64.to_be_bytes());
    buffer[40..48].copy_from_slice(&120u64.to_be_bytes());
    buffer[48..52].copy_from_slice(&0u32.to_be_bytes());
    buffer[52..54].copy_from_slice(&64u16.to_be_bytes());
    buffer[54..56].copy_from_slice(&56u16.to_be_bytes());
    buffer[56..58].copy_from_slice(&1u16.to_be_bytes());
    buffer[58..60].copy_from_slice(&64u16.to_be_bytes());
    buffer[60..62].copy_from_slice(&1u16.to_be_bytes());
    buffer[62..64].copy_from_slice(&0u16.to_be_bytes());

    let ph = 64;
    buffer[ph..ph + 4].copy_from_slice(&1u32.to_be_bytes());
    buffer[ph + 4..ph + 8].copy_from_slice(&5u32.to_be_bytes());
    buffer[ph + 8..ph + 16].copy_from_slice(&0u64.to_be_bytes());
    buffer[ph + 16..ph + 24].copy_from_slice(&0u64.to_be_bytes());
    buffer[ph + 24..ph + 32].copy_from_slice(&0u64.to_be_bytes());
    buffer[ph + 32..ph + 40].copy_from_slice(&0u64.to_be_bytes());
    buffer[ph + 40..ph + 48].copy_from_slice(&0u64.to_be_bytes());
    buffer[ph + 48..ph + 56].copy_from_slice(&8u64.to_be_bytes());

    let sh = 120;
    buffer[sh..sh + 4].copy_from_slice(&0u32.to_be_bytes());
    buffer[sh + 4..sh + 8].copy_from_slice(&0u32.to_be_bytes());
    buffer[sh + 8..sh + 16].copy_from_slice(&0u64.to_be_bytes());
    buffer[sh + 16..sh + 24].copy_from_slice(&0u64.to_be_bytes());
    buffer[sh + 24..sh + 32].copy_from_slice(&0u64.to_be_bytes());
    buffer[sh + 32..sh + 40].copy_from_slice(&0u64.to_be_bytes());
    buffer[sh + 40..sh + 44].copy_from_slice(&0u32.to_be_bytes());
    buffer[sh + 44..sh + 48].copy_from_slice(&0u32.to_be_bytes());
    buffer[sh + 48..sh + 56].copy_from_slice(&0u64.to_be_bytes());
    buffer[sh + 56..sh + 64].copy_from_slice(&0u64.to_be_bytes());

    let mut elf = elf::ELF::from_buffer(buffer).expect("Failed to parse big-endian ELF");
    let new_entry = 0xDEADBEEFCAFEu64;
    elf.header
        .entry
        .update_with(&mut elf.buffer, new_entry, hexspell::field::ByteOrder::Big)
        .unwrap();

    let reparsed = elf::ELF::from_buffer(elf.buffer).expect("Failed to re-parse ELF");
    assert_eq!(reparsed.header.entry.value, new_entry);
}

/// ELF32 header fields are parsed at 32-bit offsets
#[test]
fn test_elf32_parse() {
    let mut buffer = vec![0u8; 52];

    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[4] = 1; // ELFCLASS32
    buffer[5] = 1; // Little endian
    buffer[6] = 1;

    buffer[16..18].copy_from_slice(&2u16.to_le_bytes());
    buffer[18..20].copy_from_slice(&3u16.to_le_bytes());
    buffer[20..24].copy_from_slice(&1u32.to_le_bytes());
    buffer[24..28].copy_from_slice(&0x1000u32.to_le_bytes()); // e_entry
    buffer[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff
    buffer[32..36].copy_from_slice(&0u32.to_le_bytes()); // e_shoff
    buffer[36..40].copy_from_slice(&0u32.to_le_bytes()); // e_flags
    buffer[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
    buffer[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    buffer[44..46].copy_from_slice(&0u16.to_le_bytes()); // e_phnum
    buffer[46..48].copy_from_slice(&0u16.to_le_bytes()); // e_shentsize
    buffer[48..50].copy_from_slice(&0u16.to_le_bytes()); // e_shnum
    buffer[50..52].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    let elf = elf::ELF::from_buffer(buffer).expect("Failed to parse ELF32");
    assert!(matches!(
        elf.header.class().unwrap(),
        elf::header::ElfClass::Elf32
    ));
    assert_eq!(elf.header.ei_data.offset, 5);
    assert_eq!(elf.header.ei_data.value, 1);
    assert_eq!(elf.header.entry.value, 0x1000);
    assert_eq!(elf.header.ph_off.value, 52);
    assert_eq!(elf.header.eh_size.value, 52);
}

/// Ensure writing an ELF file to disk succeeds and preserves contents
#[test]
fn test_elf_write_file() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("Error parsing ELF file");
    let tmp_path = std::env::temp_dir().join("elf_write_test");
    elf.write_file(tmp_path.to_str().unwrap())
        .expect("Error writing ELF to disk");

    let original =
        std::fs::read("tests/samples/linux").expect("[!] Failed to read original ELF file");
    let written = std::fs::read(&tmp_path).expect("[!] Failed to read written ELF file");
    assert_eq!(original, written);

    std::fs::remove_file(tmp_path).expect("[!] Failed to remove written ELF file");
}

/// Writing an ELF file to a non-existent directory should fail
#[test]
fn test_elf_write_file_fail() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("Error parsing ELF file");
    let invalid_path = std::env::temp_dir().join("nonexistent_dir").join("elf.bin");
    let result = elf.write_file(invalid_path.to_str().unwrap());
    assert!(result.is_err());
}

/// ELF32 program header: p_flags at offset 24 (not offset 4 like ELF64)
#[test]
fn test_elf32_program_header_layout() {
    let mut buffer = vec![0u8; 52 + 32];

    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[4] = 1;
    buffer[5] = 1;
    buffer[6] = 1;
    buffer[28..32].copy_from_slice(&52u32.to_le_bytes()); // e_phoff
    buffer[42..44].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    buffer[44..46].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    let ph = 52;
    buffer[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type
    buffer[ph + 24..ph + 28].copy_from_slice(&5u32.to_le_bytes()); // p_flags at +24

    let mut elf = elf::ELF::from_buffer(buffer).expect("ELF32 phdr parse");
    assert_eq!(elf.program_headers[0].p_type(), 1);
    assert_eq!(elf.program_headers[0].p_flags(), 5);
    assert_eq!(elf.program_headers[0].p_flags_mut().offset(), ph + 24);
}

/// insert_pt_load appends a loadable segment when PHDR table has room
#[test]
fn test_elf_insert_pt_load() {
    let mut buffer = vec![0u8; 200];

    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[4] = 2;
    buffer[5] = 1;
    buffer[6] = 1;
    buffer[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    buffer[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    buffer[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    let ph = 64;
    buffer[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    buffer[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    buffer[ph + 8..ph + 16].copy_from_slice(&120u64.to_le_bytes()); // p_offset past PHDR gap

    let mut elf = elf::ELF::from_buffer(buffer).expect("parse ELF for pt_load");
    elf.insert_pt_load(elf::program::NewPtLoad {
        data: vec![0x90, 0x90, 0xCC],
        flags: elf::program::segment_flags::READ | elf::program::segment_flags::EXECUTE,
        vaddr: Some(0x2000),
        align: Some(0x1000),
    })
    .expect("insert_pt_load");

    assert_eq!(elf.program_headers.len(), 2);
    assert_eq!(elf.program_headers[1].p_type(), elf::program::PT_LOAD);
    assert_eq!(elf.program_headers[1].p_filesz(), 3);
}

/// insert_section appends section name to shstrtab and data to file end
#[test]
fn test_elf_insert_section() {
    let mut elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");
    let before = elf.section_headers.len();
    elf.insert_section(elf::section::NewSection {
        name: ".inject".to_string(),
        data: vec![0xDE, 0xAD],
        sh_type: elf::section::SHT_PROGBITS,
        flags: elf::section::section_flags::ALLOC,
        addr: None,
        offset: None,
        link: None,
        info: None,
        addralign: None,
        entsize: None,
    })
    .expect("insert_section");
    assert_eq!(elf.section_headers.len(), before + 1);
    let last = elf.section_headers.last().unwrap();
    assert_eq!(last.sh_size(), 2);
}

/// Section names resolve through .shstrtab and lookup helpers find known sections
#[test]
fn test_elf_section_names_and_lookup() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");

    // Section 0 is always the NULL section with an empty name.
    assert_eq!(elf.section_name(0).unwrap(), "");

    // Known sections are found by name and expose the expected type.
    let text_idx = elf.section_index_by_name(".text").expect(".text present");
    assert_eq!(
        elf.section_headers[text_idx].section_type(),
        elf::section::SectionType::Progbits
    );

    let dynstr = elf.section_by_name(".dynstr").expect(".dynstr present");
    assert_eq!(dynstr.section_type(), elf::section::SectionType::Strtab);

    let dynsym = elf.section_by_name(".dynsym").expect(".dynsym present");
    assert_eq!(dynsym.section_type(), elf::section::SectionType::Dynsym);

    assert!(elf.section_index_by_name(".does_not_exist").is_none());
}

/// section_data returns the exact on-disk bytes; NOBITS sections yield empty slices
#[test]
fn test_elf_section_data() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");

    let interp_idx = elf
        .section_index_by_name(".interp")
        .expect(".interp present");
    let data = elf.section_data(interp_idx).unwrap();
    // .interp holds the NUL-terminated interpreter path.
    assert!(data.ends_with(&[0]));
    let path = std::str::from_utf8(&data[..data.len() - 1]).unwrap();
    assert_eq!(path, "/lib64/ld-linux-x86-64.so.2");

    if let Some(bss_idx) = elf.section_index_by_name(".bss") {
        assert!(elf.section_data(bss_idx).unwrap().is_empty());
    }
}

/// Program header p_type maps to typed SegmentType variants
#[test]
fn test_elf_segment_types() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");
    let types: Vec<_> = elf
        .program_headers
        .iter()
        .map(|ph| ph.segment_type())
        .collect();
    assert!(types.contains(&elf::program::SegmentType::Load));
    assert!(types.contains(&elf::program::SegmentType::Dynamic));
    assert!(types.contains(&elf::program::SegmentType::Interp));
}

/// Dynamic symbols are parsed and names resolve through .dynstr
#[test]
fn test_elf_dynamic_symbols() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");
    let symtab = elf.dynamic_symbols().unwrap().expect(".dynsym present");

    assert_eq!(symtab.symbols.len(), 7);

    let names: Vec<String> = symtab
        .symbols
        .iter()
        .map(|s| symtab.name(&elf.buffer, s).unwrap())
        .collect();
    assert!(names.iter().any(|n| n == "puts"));
    assert!(names.iter().any(|n| n == "__libc_start_main"));

    // Symbol 0 is the reserved undefined symbol with an empty name.
    assert_eq!(symtab.name(&elf.buffer, &symtab.symbols[0]).unwrap(), "");
}

/// Static symbol table (.symtab) is parsed with the expected entry count
#[test]
fn test_elf_static_symbols() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");
    let symtab = elf.symbols().unwrap().expect(".symtab present");
    assert_eq!(symtab.symbols.len(), 36);
    // At least one FUNC-typed symbol should exist.
    assert!(symtab
        .symbols
        .iter()
        .any(|s| s.symbol_type() == elf::symbol::STT_FUNC));
}

/// Dynamic table exposes DT_* tags and NEEDED entries resolve to library names
#[test]
fn test_elf_dynamic_table() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");
    let dynamic = elf.dynamic().unwrap().expect(".dynamic present");

    // DT_NEEDED value is an offset into .dynstr pointing at "libc.so.6".
    let needed = dynamic
        .find(elf::dynamic::DT_NEEDED)
        .expect("DT_NEEDED present");
    let dynstr_idx = elf
        .section_index_by_name(".dynstr")
        .expect(".dynstr present");
    let dynstr = elf.section_data(dynstr_idx).unwrap();
    let start = needed.value() as usize;
    let end = start + dynstr[start..].iter().position(|&b| b == 0).unwrap();
    let name = std::str::from_utf8(&dynstr[start..end]).unwrap();
    assert_eq!(name, "libc.so.6");

    // A dynamically linked binary must reference its string and symbol tables.
    assert!(dynamic.find(elf::dynamic::DT_STRTAB).is_some());
    assert!(dynamic.find(elf::dynamic::DT_SYMTAB).is_some());
    assert_eq!(needed.tag_kind(), elf::dynamic::DynamicTag::Needed);
}

/// Relocation sections (.rela.plt / .rela.dyn) parse with unpacked symbol/type fields
#[test]
fn test_elf_relocations() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("parse linux ELF");
    let relocs = elf.relocations().unwrap();
    assert!(!relocs.is_empty());

    // Locate .rela.plt by section name.
    let plt_idx = elf
        .section_index_by_name(".rela.plt")
        .expect(".rela.plt present");
    let (_, plt_entries) = relocs
        .iter()
        .find(|(idx, _)| *idx == plt_idx)
        .expect(".rela.plt parsed");

    assert_eq!(plt_entries.len(), 1);
    let entry = &plt_entries[0];
    assert_eq!(entry.r_offset(), 0x3fd0);
    assert_eq!(entry.symbol(), 3); // puts
    assert_eq!(entry.reloc_type(), 7); // R_X86_64_JUMP_SLOT
    assert_eq!(entry.r_addend(), Some(0));

    // .rela.dyn has 8 entries.
    let dyn_idx = elf
        .section_index_by_name(".rela.dyn")
        .expect(".rela.dyn present");
    let (_, dyn_entries) = relocs
        .iter()
        .find(|(idx, _)| *idx == dyn_idx)
        .expect(".rela.dyn parsed");
    assert_eq!(dyn_entries.len(), 8);
}

#[test]
fn test_elf_hash_version_notes_groups_and_arrays() {
    let mut buffer = elf64_base(0, 18, 1, 0x400, 0x1000);
    let names = b"\0.shstrtab\0.hash\0.gnu.hash\0.gnu.version\0.gnu.version_r\0.gnu.version_d\0.note.gnu.property\0.eh_frame_hdr\0.eh_frame\0.gcc_except_table\0.group\0.init_array\0.fini_array\0.preinit_array\0.plt\0.got\0.got.plt\0";
    buffer[0x100..0x100 + names.len()].copy_from_slice(names);

    write_sh64(
        &mut buffer,
        1,
        1,
        elf::section::SHT_STRTAB,
        0,
        0,
        0x100,
        names.len() as u64,
        0,
        0,
        1,
        0,
    );

    let hash = 0x200;
    buffer[hash..hash + 4].copy_from_slice(&1u32.to_le_bytes());
    buffer[hash + 4..hash + 8].copy_from_slice(&2u32.to_le_bytes());
    buffer[hash + 8..hash + 12].copy_from_slice(&1u32.to_le_bytes());
    buffer[hash + 12..hash + 16].copy_from_slice(&0u32.to_le_bytes());
    buffer[hash + 16..hash + 20].copy_from_slice(&1u32.to_le_bytes());
    write_sh64(
        &mut buffer,
        2,
        11,
        elf::section::SHT_HASH,
        0,
        0,
        hash as u64,
        20,
        0,
        0,
        4,
        4,
    );

    let gnu_hash = 0x220;
    buffer[gnu_hash..gnu_hash + 4].copy_from_slice(&1u32.to_le_bytes());
    buffer[gnu_hash + 4..gnu_hash + 8].copy_from_slice(&1u32.to_le_bytes());
    buffer[gnu_hash + 8..gnu_hash + 12].copy_from_slice(&1u32.to_le_bytes());
    buffer[gnu_hash + 12..gnu_hash + 16].copy_from_slice(&5u32.to_le_bytes());
    buffer[gnu_hash + 16..gnu_hash + 24].copy_from_slice(&0x80u64.to_le_bytes());
    buffer[gnu_hash + 24..gnu_hash + 28].copy_from_slice(&1u32.to_le_bytes());
    buffer[gnu_hash + 28..gnu_hash + 32].copy_from_slice(&0u32.to_le_bytes());
    write_sh64(
        &mut buffer,
        3,
        17,
        elf::section::SHT_GNU_HASH,
        0,
        0,
        gnu_hash as u64,
        32,
        0,
        0,
        8,
        0,
    );

    let versym = 0x250;
    buffer[versym..versym + 2].copy_from_slice(&2u16.to_le_bytes());
    buffer[versym + 2..versym + 4].copy_from_slice(&3u16.to_le_bytes());
    write_sh64(
        &mut buffer,
        4,
        27,
        elf::section::SHT_GNU_VERSYM,
        0,
        0,
        versym as u64,
        4,
        0,
        0,
        2,
        2,
    );

    let verneed = 0x260;
    buffer[verneed..verneed + 2].copy_from_slice(&1u16.to_le_bytes());
    buffer[verneed + 2..verneed + 4].copy_from_slice(&1u16.to_le_bytes());
    buffer[verneed + 4..verneed + 8].copy_from_slice(&1u32.to_le_bytes());
    buffer[verneed + 8..verneed + 12].copy_from_slice(&16u32.to_le_bytes());
    buffer[verneed + 16..verneed + 20].copy_from_slice(&0x1234u32.to_le_bytes());
    buffer[verneed + 24..verneed + 28].copy_from_slice(&2u32.to_le_bytes());
    write_sh64(
        &mut buffer,
        5,
        40,
        elf::section::SHT_GNU_VERNEED,
        0,
        0,
        verneed as u64,
        32,
        0,
        0,
        4,
        0,
    );

    let verdef = 0x290;
    buffer[verdef..verdef + 2].copy_from_slice(&1u16.to_le_bytes());
    buffer[verdef + 4..verdef + 6].copy_from_slice(&2u16.to_le_bytes());
    write_sh64(
        &mut buffer,
        6,
        55,
        elf::section::SHT_GNU_VERDEF,
        0,
        0,
        verdef as u64,
        20,
        0,
        0,
        4,
        0,
    );

    let note = 0x2b0;
    buffer[note..note + 4].copy_from_slice(&4u32.to_le_bytes());
    buffer[note + 4..note + 8].copy_from_slice(&4u32.to_le_bytes());
    buffer[note + 8..note + 12].copy_from_slice(&5u32.to_le_bytes());
    buffer[note + 12..note + 16].copy_from_slice(b"GNU\0");
    buffer[note + 16..note + 20].copy_from_slice(&1u32.to_le_bytes());
    write_sh64(
        &mut buffer,
        7,
        70,
        elf::section::SHT_NOTE,
        0,
        0,
        note as u64,
        20,
        0,
        0,
        4,
        0,
    );

    let eh_hdr = 0x2d0;
    buffer[eh_hdr..eh_hdr + 4].copy_from_slice(&[1, 0x1b, 3, 0x3b]);
    write_sh64(
        &mut buffer,
        8,
        89,
        elf::section::SHT_PROGBITS,
        0,
        0,
        eh_hdr as u64,
        4,
        0,
        0,
        4,
        0,
    );
    write_sh64(
        &mut buffer,
        9,
        103,
        elf::section::SHT_PROGBITS,
        0,
        0,
        0x2e0,
        4,
        0,
        0,
        8,
        0,
    );
    write_sh64(
        &mut buffer,
        10,
        113,
        elf::section::SHT_PROGBITS,
        0,
        0,
        0x2f0,
        4,
        0,
        0,
        1,
        0,
    );

    let group = 0x300;
    buffer[group..group + 4].copy_from_slice(&elf::group::GRP_COMDAT.to_le_bytes());
    buffer[group + 4..group + 8].copy_from_slice(&9u32.to_le_bytes());
    write_sh64(
        &mut buffer,
        11,
        131,
        elf::section::SHT_GROUP,
        elf::section::section_flags::GROUP,
        0,
        group as u64,
        8,
        0,
        0,
        4,
        4,
    );

    for (idx, name_off, ty, off, value) in [
        (12, 138, elf::section::SHT_INIT_ARRAY, 0x320, 0x1111u64),
        (13, 150, elf::section::SHT_FINI_ARRAY, 0x328, 0x2222u64),
        (14, 162, elf::section::SHT_PREINIT_ARRAY, 0x330, 0x3333u64),
    ] {
        buffer[off..off + 8].copy_from_slice(&value.to_le_bytes());
        write_sh64(
            &mut buffer,
            idx,
            name_off,
            ty,
            0,
            0,
            off as u64,
            8,
            0,
            0,
            8,
            8,
        );
    }

    write_sh64(
        &mut buffer,
        15,
        177,
        elf::section::SHT_PROGBITS,
        0,
        0x401000,
        0x340,
        4,
        3,
        0,
        16,
        0,
    );
    write_sh64(
        &mut buffer,
        16,
        182,
        elf::section::SHT_PROGBITS,
        0,
        0x402000,
        0x350,
        4,
        3,
        0,
        8,
        0,
    );
    write_sh64(
        &mut buffer,
        17,
        187,
        elf::section::SHT_PROGBITS,
        0,
        0x403000,
        0x360,
        4,
        3,
        0,
        8,
        0,
    );

    let elf = elf::ELF::from_buffer(buffer).expect("parse synthetic ELF");
    assert_eq!(elf.sysv_hash().unwrap().unwrap().nchain.value, 2);
    assert_eq!(elf.gnu_hash().unwrap().unwrap().bloom_shift.value, 5);
    assert_eq!(elf.version_symbols().unwrap().unwrap().entries.len(), 2);
    assert_eq!(
        elf.version_needs().unwrap().unwrap().entries[0].aux.len(),
        1
    );
    assert_eq!(
        elf.version_defs().unwrap().unwrap().entries[0].vd_ndx.value,
        2
    );
    assert_eq!(
        elf.note_sections().unwrap()[0].1.entries[0].name_string(),
        "GNU"
    );
    assert_eq!(elf.gnu_property_notes().unwrap().len(), 1);
    assert_eq!(elf.eh_frame_hdr().unwrap().unwrap().version.value, 1);
    assert_eq!(elf.eh_frame().unwrap().unwrap().data.len(), 4);
    assert_eq!(elf.gcc_except_table().unwrap().unwrap().section_index, 10);
    assert!(elf.section_groups().unwrap()[0].is_comdat());
    assert_eq!(
        elf.init_array().unwrap().unwrap().entries[0].value.value,
        0x1111
    );
    assert_eq!(
        elf.fini_array().unwrap().unwrap().entries[0].value.value,
        0x2222
    );
    assert_eq!(
        elf.preinit_array().unwrap().unwrap().entries[0].value.value,
        0x3333
    );
    assert_eq!(elf.plt_got_sections().len(), 3);
}

#[test]
fn test_elf_rela_apply_and_structural_helpers() {
    let mut buffer = elf64_base(2, 1, 0, 0x400, 0x800);
    write_ph64(
        &mut buffer,
        0,
        elf::program::PT_LOAD,
        6,
        0x200,
        0x400000,
        0x80,
        0x80,
    );
    write_ph64(
        &mut buffer,
        1,
        elf::program::PT_GNU_RELRO,
        4,
        0x240,
        0x400040,
        0x20,
        0x20,
    );
    write_sh64(
        &mut buffer,
        0,
        0,
        elf::section::SHT_NULL,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
    );
    let mut elf = elf::ELF::from_buffer(buffer).expect("parse structural ELF");

    let reloc = elf::relocation::RelocationEntry::Rel64(elf::relocation::Rel64Fields {
        r_offset: hexspell::field::Field::new(0x400010, 0, 8),
        r_info: hexspell::field::Field::new(0, 8, 8),
        r_addend: Some(hexspell::field::Field::new(5, 16, 8)),
    });
    elf.apply_rela_address(&reloc, 0x1000).expect("apply rela");
    assert_eq!(&elf.buffer[0x210..0x218], &0x1005u64.to_le_bytes());
    assert_eq!(elf.gnu_relro_segments().len(), 1);

    let out_of_bounds = elf::relocation::RelocationEntry::Rel64(elf::relocation::Rel64Fields {
        r_offset: hexspell::field::Field::new(0x1000, 0, 8),
        r_info: hexspell::field::Field::new(0, 8, 8),
        r_addend: Some(hexspell::field::Field::new(0, 16, 8)),
    });
    assert!(matches!(
        elf.apply_rela_address(&out_of_bounds, 0),
        Err(FileParseError::BufferOverflow)
    ));

    elf.insert_section(elf::section::NewSection {
        name: ".x".to_string(),
        data: vec![1, 2, 3, 4],
        sh_type: elf::section::SHT_PROGBITS,
        flags: elf::section::section_flags::ALLOC,
        addr: Some(0x400020),
        offset: Some(0x220),
        link: None,
        info: None,
        addralign: Some(4),
        entsize: None,
    })
    .expect("insert arbitrary section");
    assert!(elf.section_index_by_name(".shstrtab").is_some());
    assert_eq!(
        elf.section_data_by_name(".x").unwrap().unwrap(),
        &[1, 2, 3, 4]
    );
    assert!(elf.program_headers[0].p_filesz() > 0x80);
}

#[test]
fn test_elf_split_and_merge_load_segments() {
    let mut split_buffer = elf64_base(1, 1, 0, 0x400, 0x800);
    write_ph64(
        &mut split_buffer,
        0,
        elf::program::PT_LOAD,
        4,
        0x200,
        0x400000,
        0x80,
        0x80,
    );
    write_sh64(
        &mut split_buffer,
        0,
        0,
        elf::section::SHT_NULL,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    let mut elf = elf::ELF::from_buffer(split_buffer).expect("parse split ELF");
    elf.split_load_segment(0, 0x240).expect("split PT_LOAD");
    assert_eq!(elf.program_headers.len(), 2);
    assert_eq!(elf.program_headers[0].p_filesz(), 0x40);
    assert_eq!(elf.program_headers[1].p_offset(), 0x240);

    let mut merge_buffer = elf64_base(2, 1, 0, 0x400, 0x800);
    write_ph64(
        &mut merge_buffer,
        0,
        elf::program::PT_LOAD,
        4,
        0x200,
        0x400000,
        0x20,
        0x20,
    );
    write_ph64(
        &mut merge_buffer,
        1,
        elf::program::PT_LOAD,
        4,
        0x220,
        0x400020,
        0x20,
        0x20,
    );
    write_sh64(
        &mut merge_buffer,
        0,
        0,
        elf::section::SHT_NULL,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    let mut elf = elf::ELF::from_buffer(merge_buffer).expect("parse merge ELF");
    assert_eq!(elf.merge_adjacent_load_segments().unwrap(), 1);
    assert_eq!(elf.program_headers[0].p_filesz(), 0x40);
    assert_eq!(elf.program_headers[1].p_type(), elf::program::PT_NULL);
}

#[test]
fn test_elf_extended_shnum_core_and_ar_archive() {
    let mut buffer = elf64_base(0, 0, 0, 0x400, 0x800);
    buffer[16..18].copy_from_slice(&4u16.to_le_bytes());
    write_sh64(
        &mut buffer,
        0,
        0,
        elf::section::SHT_NULL,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        0,
    );
    let elf = elf::ELF::from_buffer(buffer).expect("parse extended shnum");
    assert_eq!(elf.section_headers.len(), 2);
    assert!(elf.is_core());

    let mut ar =
        b"!<arch>\nhello.o/        0           0     0     100644  4         `\nELF!".to_vec();
    if ar.len() % 2 != 0 {
        ar.push(b'\n');
    }
    let archive = elf::ELF::parse_archive(&ar).expect("parse ar");
    assert_eq!(archive.members.len(), 1);
    assert_eq!(archive.members[0].data(&ar).unwrap(), b"ELF!");
}

fn elf64_base(phnum: u16, shnum: u16, shstrndx: u16, shoff: usize, len: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; len];
    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[4] = 2;
    buffer[5] = 1;
    buffer[6] = 1;
    buffer[16..18].copy_from_slice(&2u16.to_le_bytes());
    buffer[20..24].copy_from_slice(&1u32.to_le_bytes());
    buffer[32..40].copy_from_slice(&64u64.to_le_bytes());
    buffer[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    buffer[52..54].copy_from_slice(&64u16.to_le_bytes());
    buffer[54..56].copy_from_slice(&56u16.to_le_bytes());
    buffer[56..58].copy_from_slice(&phnum.to_le_bytes());
    buffer[58..60].copy_from_slice(&64u16.to_le_bytes());
    buffer[60..62].copy_from_slice(&shnum.to_le_bytes());
    buffer[62..64].copy_from_slice(&shstrndx.to_le_bytes());
    buffer
}

#[allow(clippy::too_many_arguments)]
fn write_sh64(
    buffer: &mut [u8],
    index: usize,
    name: u32,
    ty: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
) {
    let base = 0x400 + index * 64;
    buffer[base..base + 4].copy_from_slice(&name.to_le_bytes());
    buffer[base + 4..base + 8].copy_from_slice(&ty.to_le_bytes());
    buffer[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
    buffer[base + 16..base + 24].copy_from_slice(&addr.to_le_bytes());
    buffer[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
    buffer[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
    buffer[base + 40..base + 44].copy_from_slice(&link.to_le_bytes());
    buffer[base + 44..base + 48].copy_from_slice(&info.to_le_bytes());
    buffer[base + 48..base + 56].copy_from_slice(&align.to_le_bytes());
    buffer[base + 56..base + 64].copy_from_slice(&entsize.to_le_bytes());
}

fn write_ph64(
    buffer: &mut [u8],
    index: usize,
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
) {
    let base = 64 + index * 56;
    buffer[base..base + 4].copy_from_slice(&ty.to_le_bytes());
    buffer[base + 4..base + 8].copy_from_slice(&flags.to_le_bytes());
    buffer[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
    buffer[base + 16..base + 24].copy_from_slice(&vaddr.to_le_bytes());
    buffer[base + 24..base + 32].copy_from_slice(&vaddr.to_le_bytes());
    buffer[base + 32..base + 40].copy_from_slice(&filesz.to_le_bytes());
    buffer[base + 40..base + 48].copy_from_slice(&memsz.to_le_bytes());
    buffer[base + 48..base + 56].copy_from_slice(&0x1000u64.to_le_bytes());
}
