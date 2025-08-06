/// HexSpell PE
/// ====================================
/// File for testing PE functionalities
///
/// REFERENCES
/// -----------
/// PE Structure       =>  https://wiki.osdev.org/PE
/// PE Viewer Online   =>  https://speedtesting.herokuapp.com/peviewer/
///
use std::fs;
use toml::Value;

use hexspell::errors::FileParseError;
use hexspell::pe; // <-- Testing module

/// ========================================
/// Testing reading and parsing in a PE file
/// ========================================
#[test]
fn test_pe_parse() {
    let toml_contents: String =
        fs::read_to_string("tests/tests.toml").expect("Failed to read tests.toml");
    let data: Value = toml_contents
        .parse::<Value>()
        .expect("Failed to parse TOML");

    // PE FILES (pe, pe_section)
    if let Some(pe) = data.get("pe").and_then(|v| v.as_table()) {
        for (key, value) in pe {
            let file_extension: &str = value
                .get("file_extension")
                .and_then(|v| v.as_str())
                .unwrap_or("exe");
            let file_name: String = format!("tests/samples/{}.{}", key, file_extension);
            let mut pe: pe::PE = pe::PE::from_file(&file_name).expect("Failed to parse PE");

            // Getting real values from test.toml
            let architecture = value.get("architecture").and_then(|v| v.as_str()).unwrap();
            let checksum = value
                .get("checksum")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let entry_point = value
                .get("entry_point")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let size_of_image = value
                .get("size_of_image")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let number_of_sections = value
                .get("number_of_sections")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let section_alignment = value
                .get("section_alignment")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let file_alignment = value
                .get("file_alignment")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let base_of_code = value
                .get("base_of_code")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let base_of_data = value
                .get("base_of_data")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let size_of_headers = value
                .get("size_of_headers")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let subsystem = value
                .get("subsystem")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();
            let dll_characteristics = value
                .get("dll_characteristics")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                .unwrap();

            // Testing parse params result
            assert_eq!(
                pe.header.architecture.value.to_string(),
                architecture,
                "Architecture does not match for {}",
                key
            );
            assert_eq!(
                pe.header.checksum.value, checksum,
                "Checksum does not match for {}",
                key
            );
            assert_eq!(
                pe.header.entry_point.value, entry_point,
                "Entry point does not match for {}",
                key
            );
            assert_eq!(
                pe.header.size_of_image.value, size_of_image,
                "Size of image does not match for {}",
                key
            );
            assert_eq!(
                pe.header.number_of_sections.value, number_of_sections,
                "Number of sections does not match for {}",
                key
            );
            assert_eq!(
                pe.header.section_alignment.value, section_alignment,
                "Section alignment of sections does not match for {}",
                key
            );
            assert_eq!(
                pe.header.file_alignment.value, file_alignment,
                "File alignment does not match for {}",
                key
            );
            assert_eq!(
                pe.header.base_of_code.value, base_of_code,
                "Base of code does not match for {}",
                key
            );
            assert_eq!(
                pe.header.base_of_data.value, base_of_data,
                "Base of data does not match for {}",
                key
            );
            assert_eq!(
                pe.header.size_of_headers.value, size_of_headers,
                "Size of headers does not match for {}",
                key
            );
            assert_eq!(
                pe.header.subsystem.value, subsystem,
                "Subsystem does not match for {}",
                key
            );
            assert_eq!(
                pe.header.dll_characteristics.value, dll_characteristics,
                "DLL characteristics does not match for {}",
                key
            );
            match pe.header.pe_type {
                pe::header::PEType::PE32 => {
                    // Convertir image_base desde hexadecimal a u32
                    let image_base = value
                        .get("image_base")
                        .and_then(|v| v.as_str())
                        .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                        .unwrap();

                    // Comprobar si el valor de image_base es de tipo Base32
                    match pe.header.image_base.value {
                        pe::header::ImageBase::Base32(base) => {
                            assert_eq!(
                                base, image_base,
                                "[PE32] Image base does not match for {}",
                                key
                            )
                        }
                        _ => panic!("Incorrect type for image_base, expected u32"),
                    }
                }
                pe::header::PEType::PE32Plus => {
                    // Convertir image_base desde hexadecimal a u64
                    let image_base = value
                        .get("image_base")
                        .and_then(|v| v.as_str())
                        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                        .unwrap();

                    // Comprobar si el valor de image_base es de tipo Base64
                    match pe.header.image_base.value {
                        pe::header::ImageBase::Base64(base) => {
                            assert_eq!(
                                base, image_base,
                                "[PE32+] Image base does not match for {}",
                                key
                            )
                        }
                        _ => panic!("Incorrect type for image_base, expected u64"),
                    }
                }
            }

            // Testing some functions
            let checksum_calculed: u32 = pe.calc_checksum();
            assert_eq!(
                pe.header.checksum.value, checksum_calculed,
                "Calculed checksum doesnt fit the original checksum"
            );

            // Updating params
            let new_entry: u32 = 0x32EDu32;
            pe.header
                .entry_point
                .update(&mut pe.buffer, new_entry)
                .unwrap();
            assert_eq!(
                pe.header.entry_point.value, new_entry,
                "Entry point didnt changed"
            );

            let new_section_name = String::from(".test");
            pe.sections[0]
                .name
                .update(&mut pe.buffer, &new_section_name)
                .unwrap();
            assert_eq!(
                pe.sections[0].name.value, new_section_name,
                "Section name didnt changed"
            );
        }
    }
}

/// ========================================
/// Testing the manipulation of the executable
/// ========================================
#[test]
fn test_pe_shellcode_injection() {
    if !std::path::Path::new(&"./tests/out/").exists() {
        fs::create_dir("./tests/out/").unwrap();
    }

    // msfvenom -p windows/messagebox TITLE="Hello" TEXT="I'm in your code" -f rust
    let shellcode: [u8; 267] = [
        0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0xf4, 0x31, 0xd2, 0xb2, 0x77, 0x31, 0xc9, 0x64, 0x8b,
        0x71, 0x30, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x1c, 0x8b, 0x46, 0x08, 0x8b, 0x7e, 0x20, 0x8b,
        0x36, 0x38, 0x4f, 0x18, 0x75, 0xf3, 0x59, 0x01, 0xd1, 0xff, 0xe1, 0x60, 0x8b, 0x6c, 0x24,
        0x24, 0x8b, 0x45, 0x3c, 0x8b, 0x54, 0x28, 0x78, 0x01, 0xea, 0x8b, 0x4a, 0x18, 0x8b, 0x5a,
        0x20, 0x01, 0xeb, 0xe3, 0x34, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xee, 0x31, 0xff, 0x31, 0xc0,
        0xfc, 0xac, 0x84, 0xc0, 0x74, 0x07, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xeb, 0xf4, 0x3b, 0x7c,
        0x24, 0x28, 0x75, 0xe1, 0x8b, 0x5a, 0x24, 0x01, 0xeb, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x5a,
        0x1c, 0x01, 0xeb, 0x8b, 0x04, 0x8b, 0x01, 0xe8, 0x89, 0x44, 0x24, 0x1c, 0x61, 0xc3, 0xb2,
        0x08, 0x29, 0xd4, 0x89, 0xe5, 0x89, 0xc2, 0x68, 0x8e, 0x4e, 0x0e, 0xec, 0x52, 0xe8, 0x9f,
        0xff, 0xff, 0xff, 0x89, 0x45, 0x04, 0xbb, 0x7e, 0xd8, 0xe2, 0x73, 0x87, 0x1c, 0x24, 0x52,
        0xe8, 0x8e, 0xff, 0xff, 0xff, 0x89, 0x45, 0x08, 0x68, 0x6c, 0x6c, 0x20, 0x41, 0x68, 0x33,
        0x32, 0x2e, 0x64, 0x68, 0x75, 0x73, 0x65, 0x72, 0x30, 0xdb, 0x88, 0x5c, 0x24, 0x0a, 0x89,
        0xe6, 0x56, 0xff, 0x55, 0x04, 0x89, 0xc2, 0x50, 0xbb, 0xa8, 0xa2, 0x4d, 0xbc, 0x87, 0x1c,
        0x24, 0x52, 0xe8, 0x5f, 0xff, 0xff, 0xff, 0x68, 0x6f, 0x58, 0x20, 0x20, 0x68, 0x48, 0x65,
        0x6c, 0x6c, 0x31, 0xdb, 0x88, 0x5c, 0x24, 0x05, 0x89, 0xe3, 0x68, 0x58, 0x20, 0x20, 0x20,
        0x68, 0x63, 0x6f, 0x64, 0x65, 0x68, 0x6f, 0x75, 0x72, 0x20, 0x68, 0x69, 0x6e, 0x20, 0x79,
        0x68, 0x49, 0x27, 0x6d, 0x20, 0x31, 0xc9, 0x88, 0x4c, 0x24, 0x10, 0x89, 0xe1, 0x31, 0xd2,
        0x52, 0x53, 0x51, 0x52, 0xff, 0xd0, 0x31, 0xc0, 0x50, 0xff, 0x55, 0x08,
    ];

    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("[!] Error opening PE file");

    // Create new section header based on basic parameters
    let new_section_header = pe
        .generate_section_header(
            ".shell",               // Name for the new section
            shellcode.len() as u32, // The size of the data it has to store
            pe::section::Characteristics::Code.to_u32() // Basic characteristics for a shellcode
            + pe::section::Characteristics::Readable.to_u32()
            + pe::section::Characteristics::Executable.to_u32(),
        )
        .expect("[!] Error generating new section header");

    pe.add_section(new_section_header, shellcode.to_vec())
        .expect("[!] Error adding new section into PE");
    pe.header
        .entry_point
        .update(
            &mut pe.buffer,
            pe.sections.last().unwrap().virtual_address.value,
        )
        .unwrap();

    pe.write_file("tests/out/modified.exe")
        .expect("[!] Error writing new PE to disk");

    std::fs::remove_file("tests/out/modified.exe").expect("[!] Failed to remove modified PE file");
}

/// Parsing an invalid PE buffer should return an error
#[test]
fn test_pe_invalid_buffer() {
    let buffer = vec![0u8; 10];
    let result = pe::PE::from_buffer(buffer);
    assert!(matches!(result, Err(FileParseError::InvalidFileFormat)));
}

#[test]
fn test_pe_write_file() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Error parsing PE file");
    let tmp_path = std::env::temp_dir().join("pe_write_test.exe");
    pe.write_file(tmp_path.to_str().unwrap())
        .expect("Error writing PE to disk");

    let original =
        std::fs::read("tests/samples/sample1.exe").expect("[!] Failed to read original PE file");
    let written = std::fs::read(&tmp_path).expect("[!] Failed to read written PE file");
    assert_eq!(original, written);

    std::fs::remove_file(tmp_path).expect("[!] Failed to remove written PE file");
}

#[test]
fn test_pe_write_file_fail() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Error parsing PE file");
    let invalid_path = std::env::temp_dir().join("nonexistent_dir").join("pe.bin");
    let result = pe.write_file(invalid_path.to_str().unwrap());
    assert!(result.is_err());
}
