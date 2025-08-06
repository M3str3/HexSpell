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
use hexspell::macho; // <-- Testing module

/// ============================================
/// Testing reading and parsing in a Mach-O file
/// ============================================
#[test]
fn test_macho_parse() {
    let toml_contents: String =
        fs::read_to_string("tests/tests.toml").expect("Failed to read tests.toml");
    let data: Value = toml_contents
        .parse::<Value>()
        .expect("Failed to parse TOML");

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

/// Parsing a buffer without a valid Mach-O magic number should fail
#[test]
fn test_macho_invalid_buffer() {
    let buffer = vec![0u8; 4];
    let result = macho::MachO::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
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
