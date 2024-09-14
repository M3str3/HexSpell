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
