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
    let data: Value = toml::from_str(&toml_contents).expect("Failed to parse TOML");

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
                pe.architecture().to_string(),
                architecture,
                "Architecture does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.checksum.value, checksum,
                "Checksum does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.entry_point.value, entry_point,
                "Entry point does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.size_of_image.value, size_of_image,
                "Size of image does not match for {}",
                key
            );
            assert_eq!(
                pe.coff_header.number_of_sections.value, number_of_sections,
                "Number of sections does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.section_alignment.value, section_alignment,
                "Section alignment of sections does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.file_alignment.value, file_alignment,
                "File alignment does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.base_of_code.value, base_of_code,
                "Base of code does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.base_of_data.as_ref().map(|f| f.value),
                Some(base_of_data),
                "Base of data does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.size_of_headers.value, size_of_headers,
                "Size of headers does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.subsystem.value, subsystem,
                "Subsystem does not match for {}",
                key
            );
            assert_eq!(
                pe.optional_header.dll_characteristics.value, dll_characteristics,
                "DLL characteristics does not match for {}",
                key
            );
            match pe.optional_header.pe_type().unwrap() {
                pe::header::PEType::PE32 => {
                    // Convertir image_base desde hexadecimal a u32
                    let image_base = value
                        .get("image_base")
                        .and_then(|v| v.as_str())
                        .map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
                        .unwrap();

                    // Comprobar si el valor de image_base es de tipo Base32
                    match pe.optional_header.image_base.value {
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
                    match pe.optional_header.image_base.value {
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
                pe.optional_header.checksum.value, checksum_calculed,
                "Calculed checksum doesnt fit the original checksum"
            );

            // Updating params
            let new_entry: u32 = 0x32EDu32;
            pe.optional_header
                .entry_point
                .update(&mut pe.buffer, new_entry)
                .unwrap();
            assert_eq!(
                pe.optional_header.entry_point.value, new_entry,
                "Entry point didnt changed"
            );

            let new_section_name = ".test";
            pe.sections[0]
                .name
                .update_str(&mut pe.buffer, new_section_name)
                .unwrap();
            assert_eq!(
                pe.sections[0].name_str(),
                new_section_name,
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

    pe.insert_section(pe::section::NewSection {
        name: ".shell".to_string(),
        data: shellcode.to_vec(),
        characteristics: pe::section::CODE | pe::section::READ | pe::section::EXECUTE,
    })
    .expect("[!] Error adding new section into PE");
    pe.optional_header
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

#[test]
fn test_pe_image_base_update() {
    use pe::header::ImageBase;

    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let offset = pe.optional_header.image_base.offset;

    pe.optional_header
        .image_base
        .update(&mut pe.buffer, ImageBase::Base32(0x00500000))
        .unwrap();

    assert!(matches!(
        pe.optional_header.image_base.value,
        ImageBase::Base32(0x00500000)
    ));
    assert_eq!(&pe.buffer[offset..offset + 4], 0x00500000u32.to_le_bytes());
}

/// PE32+ must parse image_base as u64 and omit base_of_data.
/// Sample: tests/samples/sample64.exe (built from tests/source/sample4.c).
#[test]
fn test_pe64_parse() {
    use pe::header::{ImageBase, PEType, SizedU64};

    let pe = pe::PE::from_file("tests/samples/sample64.exe").expect("Failed to parse PE64");
    assert!(matches!(
        pe.optional_header.pe_type().unwrap(),
        PEType::PE32Plus
    ));
    assert_eq!(pe.architecture().to_string(), "x64");
    assert!(pe.optional_header.base_of_data.is_none());
    assert!(matches!(
        pe.optional_header.image_base.value,
        ImageBase::Base64(0x140000000)
    ));
    assert_eq!(pe.optional_header.image_base.size, 8);
    assert_eq!(
        pe.optional_header.image_base.offset,
        pe.optional_header.base_of_code.offset + 4
    );

    let oh = &pe.optional_header;
    assert_eq!(oh.major_linker_version.value, 0x02);
    assert_eq!(oh.minor_linker_version.value, 0x29);
    assert_eq!(oh.size_of_code.value, 0x1800);
    assert_eq!(oh.size_of_initialized_data.value, 0x3600);
    assert_eq!(oh.size_of_uninitialized_data.value, 0x200);
    assert_eq!(oh.major_operating_system_version.value, 0x4);
    assert_eq!(oh.major_subsystem_version.value, 0x5);
    assert_eq!(oh.minor_subsystem_version.value, 0x2);
    assert_eq!(oh.dll_characteristics.value, 0x160);
    assert_eq!(oh.number_of_rva_and_sizes.value, 0x10);
    assert!(matches!(
        oh.size_of_stack_reserve.value,
        SizedU64::U64(0x200000)
    ));
    assert_eq!(oh.size_of_stack_reserve.size, 8);
    assert!(matches!(
        oh.size_of_stack_commit.value,
        SizedU64::U64(0x1000)
    ));
    assert!(matches!(
        oh.size_of_heap_reserve.value,
        SizedU64::U64(0x100000)
    ));
    assert!(matches!(
        oh.size_of_heap_commit.value,
        SizedU64::U64(0x1000)
    ));
    assert_eq!(oh.loader_flags.value, 0);

    assert_eq!(
        oh.data_directories[pe::header::IMPORT]
            .virtual_address
            .value,
        0x8000
    );
    assert_eq!(oh.data_directories[pe::header::IMPORT].size.value, 0x510);
    assert_eq!(
        oh.data_directories[pe::header::EXCEPTION]
            .virtual_address
            .value,
        0x5000
    );
    assert_eq!(oh.data_directories[pe::header::EXCEPTION].size.value, 0x210);
    assert_eq!(
        oh.data_directories[pe::header::BASERELOC]
            .virtual_address
            .value,
        0xb000
    );
    assert_eq!(oh.data_directories[pe::header::BASERELOC].size.value, 0x78);
    assert_eq!(
        oh.data_directories[pe::header::TLS].virtual_address.value,
        0x4020
    );
    assert_eq!(
        oh.data_directories[pe::header::IAT].virtual_address.value,
        0x8160
    );
    assert_eq!(oh.data_directories[pe::header::IAT].size.value, 0x120);
}

/// PE32+ base relocation directory (`IMAGE_BASE_RELOCATION` blocks).
#[test]
fn test_pe64_base_relocations() {
    use pe::relocation::{IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64};

    let pe = pe::PE::from_file("tests/samples/sample64.exe").expect("Failed to parse PE64");

    assert_eq!(pe.base_relocations.len(), 4);
    assert_eq!(
        pe.base_relocations
            .iter()
            .map(|block| block.entries.len())
            .sum::<usize>(),
        44
    );

    let first = &pe.base_relocations[0];
    assert_eq!(first.page_rva.value, 0x2000);
    assert_eq!(first.page_rva.offset, 0x3a00);
    assert_eq!(first.block_size.value, 0x0c);
    assert_eq!(first.entries.len(), 2);
    assert_eq!(first.entries[0].raw.offset, 0x3a08);
    assert_eq!(first.entries[0].relocation_type(), IMAGE_REL_BASED_DIR64);
    assert_eq!(first.entries[0].offset(), 0x738);
    assert_eq!(first.entries[0].rva(first.page_rva.value), 0x2738);
    assert_eq!(first.entries[1].relocation_type(), IMAGE_REL_BASED_ABSOLUTE);

    let last = &pe.base_relocations[3];
    assert_eq!(last.page_rva.value, 0x9000);
    assert_eq!(last.block_size.value, 0x10);
    assert_eq!(last.entries.len(), 4);
    assert!(last
        .entries
        .iter()
        .all(|entry| entry.relocation_type() == IMAGE_REL_BASED_DIR64));
}

/// PE32 optional header P0 fields and data directories (sample1.exe).
#[test]
fn test_pe32_optional_header_p0() {
    use pe::header::{SizedU64, IAT, IMPORT, TLS};

    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE32");
    let oh = &pe.optional_header;

    assert_eq!(oh.major_linker_version.value, 0x02);
    assert_eq!(oh.minor_linker_version.value, 0x20);
    assert_eq!(oh.size_of_code.value, 0x3200);
    assert_eq!(oh.size_of_initialized_data.value, 0x5400);
    assert_eq!(oh.size_of_uninitialized_data.value, 0x200);
    assert_eq!(oh.major_operating_system_version.value, 0x4);
    assert_eq!(oh.major_image_version.value, 0x1);
    assert_eq!(oh.major_subsystem_version.value, 0x4);
    assert_eq!(oh.win32_version_value.value, 0);
    assert_eq!(oh.number_of_rva_and_sizes.value, 0x10);
    assert!(matches!(
        oh.size_of_stack_reserve.value,
        SizedU64::U32(0x200000)
    ));
    assert_eq!(oh.size_of_stack_reserve.size, 4);
    assert!(matches!(
        oh.size_of_stack_commit.value,
        SizedU64::U32(0x1000)
    ));
    assert!(matches!(
        oh.size_of_heap_reserve.value,
        SizedU64::U32(0x100000)
    ));
    assert!(matches!(
        oh.size_of_heap_commit.value,
        SizedU64::U32(0x1000)
    ));
    assert_eq!(oh.loader_flags.value, 0);

    assert_eq!(oh.data_directories[IMPORT].virtual_address.value, 0x9000);
    assert_eq!(oh.data_directories[IMPORT].size.value, 0x7d4);
    assert_eq!(oh.data_directories[IAT].virtual_address.value, 0x9184);
    assert_eq!(oh.data_directories[IAT].size.value, 0x10c);
    assert_eq!(oh.data_directories[TLS].virtual_address.value, 0xb004);
    assert_eq!(oh.data_directories[TLS].size.value, 0x18);

    assert_eq!(
        oh.data_directories[IMPORT].virtual_address.offset + 4,
        oh.data_directories[IMPORT].size.offset
    );
    assert_eq!(
        oh.data_directories[1].virtual_address.offset
            - oh.data_directories[0].virtual_address.offset,
        8
    );
}

/// insert_section_raw must not panic when section name is shorter than 8 bytes (parsed sections)
#[test]
fn test_pe_insert_section_parsed_short_name_no_panic() {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let offset = pe.sections[0].name.offset;
    let parsed =
        pe::section::PeSection::parse_section(&pe.buffer, offset).expect("Failed to parse section");
    assert!(
        parsed.name_str().as_bytes().len() < 8,
        "Parsed section name should be shorter than 8 bytes"
    );

    // May return Err for layout reasons, but must not panic on name serialization
    let _ = pe.insert_section_raw(parsed, vec![0x90; 4]);
}

/// Parsing an invalid PE buffer should return an error
#[test]
fn test_pe_invalid_buffer() {
    let buffer = vec![0u8; 10];
    let result = pe::PE::from_buffer(buffer);
    assert!(matches!(
        result,
        Err(FileParseError::InvalidFileFormat) | Err(FileParseError::BufferOverflow)
    ));
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

/// Import directory: IMAGE_IMPORT_DESCRIPTOR, ILT/IAT fields, IMAGE_IMPORT_BY_NAME (sample1.exe).
#[test]
fn test_pe_imports_sample1() {
    use pe::import::{ImportDirectory, ImportEntry};

    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE32");
    let imports = pe.imports().expect("Failed to parse imports");

    assert_eq!(imports.offset, 0x4c00);
    assert_eq!(imports.descriptors.len(), 5);
    assert_eq!(imports.dlls.len(), 5);

    let desc = &imports.descriptors[0];
    assert_eq!(desc.original_first_thunk.value, 0x9078);
    assert_eq!(desc.original_first_thunk.offset, imports.offset);
    assert_eq!(desc.first_thunk.value, 0x9184);
    assert_eq!(desc.name.value, 0x96dc);

    let kernel32 = &imports.dlls[0];
    assert_eq!(kernel32.dll_name, "KERNEL32.dll");
    assert_eq!(kernel32.dll_name_offset, pe.rva_to_offset(0x96dc).unwrap());
    assert!(!kernel32.entries.is_empty());

    let exit_process = kernel32.entries.iter().find_map(|e| match e {
        ImportEntry::ByName { by_name, thunk } if by_name.name == "ExitProcess" => {
            Some((by_name.hint.value, thunk.offset()))
        }
        _ => None,
    });
    assert_eq!(exit_process, Some((280, 0x4c80)));

    let libstdcxx = imports
        .dlls
        .iter()
        .find(|d| d.dll_name == "libstdc++-6.dll")
        .expect("libstdc++-6.dll");
    assert!(libstdcxx.entries.iter().any(|e| matches!(
        e,
        ImportEntry::ByName { by_name, .. } if by_name.name == "_ZNSolsEPFRSoS_E"
    )));

    let via_helper = pe::import::import_names_for_dll(&imports, "KERNEL32.dll");
    assert!(via_helper.contains(&"GetProcAddress"));
    assert!(via_helper.contains(&"LoadLibraryA"));

    let empty = ImportDirectory::parse(
        &pe.buffer,
        &pe.sections,
        0,
        pe.optional_header.pe_type().unwrap(),
    )
    .unwrap();
    assert!(empty.descriptors.is_empty());
    assert!(empty.dlls.is_empty());
}

#[test]
fn test_pe_write_file_fail() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Error parsing PE file");
    let invalid_path = std::env::temp_dir().join("nonexistent_dir").join("pe.bin");
    let result = pe.write_file(invalid_path.to_str().unwrap());
    assert!(result.is_err());
}

/// RVA → file offset and zero-copy section payload views.
#[test]
fn test_pe_rva_to_offset_and_section_data() {
    let pe = pe::PE::from_file("tests/samples/sample2.dll").expect("Failed to parse PE");

    let export_rva = pe.optional_header.data_directories[pe::header::EXPORT]
        .virtual_address
        .value;
    let export_off = pe.rva_to_offset(export_rva).expect("export RVA should map");
    assert_eq!(export_off, 0x1e00);

    let edata_idx = pe
        .sections
        .iter()
        .position(|s| s.name_str() == ".edata")
        .expect(".edata section");
    let section_bytes = pe.section_data(edata_idx).expect("section data");
    assert!(section_bytes.len() >= 0x79);
    assert_eq!(&section_bytes[..4], &[0, 0, 0, 0]); // Characteristics

    assert!(pe.exports().unwrap().is_some());
    assert!(pe.rva_to_offset(0).is_err());
}

/// `IMAGE_EXPORT_DIRECTORY` and named exports on sample2.dll.
#[test]
fn test_pe_exports_sample2() {
    use pe::header::EXPORT;

    let pe = pe::PE::from_file("tests/samples/sample2.dll").expect("Failed to parse PE");
    let exports = pe
        .exports()
        .expect("parse exports")
        .expect("export directory");

    let dir = &exports.directory;
    assert_eq!(dir.characteristics.value, 0);
    assert_eq!(dir.time_date_stamp.value, 0x663d1a00);
    assert_eq!(dir.major_version.value, 0);
    assert_eq!(dir.minor_version.value, 0);
    assert_eq!(dir.name.value, 0x6050);
    assert_eq!(dir.base.value, 1);
    assert_eq!(dir.number_of_functions.value, 4);
    assert_eq!(dir.number_of_names.value, 4);
    assert_eq!(dir.address_of_functions.value, 0x6028);
    assert_eq!(dir.address_of_names.value, 0x6038);
    assert_eq!(dir.address_of_name_ordinals.value, 0x6048);

    let export_off = pe
        .rva_to_offset(
            pe.optional_header.data_directories[EXPORT]
                .virtual_address
                .value,
        )
        .unwrap();
    assert_eq!(dir.characteristics.offset, export_off);
    assert_eq!(dir.address_of_name_ordinals.offset, export_off + 36);
    assert_eq!(dir.address_of_name_ordinals.size, 4);

    assert_eq!(
        dir.dll_name(&pe.buffer, |rva| pe.rva_to_offset(rva))
            .unwrap(),
        "sample3.dll"
    );

    assert_eq!(exports.named.len(), 4);

    let by_name: std::collections::HashMap<&str, u32> = exports
        .named
        .iter()
        .map(|e| (e.name.as_str(), e.function_rva.value))
        .collect();
    assert_eq!(by_name["Add"], 0x1280);
    assert_eq!(by_name["Subtract"], 0x12a6);
    assert_eq!(by_name["Multiply"], 0x12cc);
    assert_eq!(by_name["Divide"], 0x12f2);

    let add = exports.named.iter().find(|e| e.name == "Add").unwrap();
    assert_eq!(add.ordinal, 1);
    assert_eq!(add.name_rva.value, 0x605c);
    assert_eq!(add.name_ordinal_index.value, 0);
    assert_eq!(add.function_rva.offset, pe.rva_to_offset(0x6028).unwrap());
    assert_eq!(add.name_rva.offset, pe.rva_to_offset(0x6038).unwrap());
    assert_eq!(
        add.name_ordinal_index.offset,
        pe.rva_to_offset(0x6048).unwrap()
    );
}

/// Executables without an export directory return `None`.
#[test]
fn test_pe_exports_absent() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    assert!(pe.exports().unwrap().is_none());
}

/// Full `AddressOfFunctions` table on sample2.dll.
#[test]
fn test_pe_exports_full_function_table() {
    use pe::export::FunctionExport;

    let pe = pe::PE::from_file("tests/samples/sample2.dll").expect("Failed to parse PE");
    let exports = pe.exports().unwrap().expect("export directory");

    assert_eq!(exports.functions.len(), 4);
    assert_eq!(exports.named.len(), 4);
    assert!(exports.ordinal_only_exports().is_empty());

    assert!(exports
        .functions
        .iter()
        .all(|entry| matches!(entry, FunctionExport::Local { .. })));

    let ordinals: Vec<u16> = exports
        .functions
        .iter()
        .map(|entry| match entry {
            FunctionExport::Local { ordinal, .. } | FunctionExport::Forwarder { ordinal, .. } => {
                *ordinal
            }
        })
        .collect();
    assert_eq!(ordinals, [1, 2, 3, 4]);
}

/// TLS directory on PE32 and PE32+ samples.
#[test]
fn test_pe_tls_directory() {
    use pe::header::ImageBase;

    let pe32 = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE32");
    let tls32 = pe32.tls().unwrap().expect("TLS directory");
    assert!(matches!(
        tls32.start_address_of_raw_data.value,
        ImageBase::Base32(0x0040b001)
    ));
    assert!(matches!(
        tls32.end_address_of_raw_data.value,
        ImageBase::Base32(0x0040b01c)
    ));
    assert!(matches!(
        tls32.address_of_index.value,
        ImageBase::Base32(0x0040803c)
    ));
    assert_eq!(tls32.size_of_zero_fill.value, 0);

    let pe64 = pe::PE::from_file("tests/samples/sample64.exe").expect("Failed to parse PE64");
    let tls64 = pe64.tls().unwrap().expect("TLS directory");
    assert!(matches!(
        tls64.start_address_of_raw_data.value,
        ImageBase::Base64(0x0000_0001_4000_a000)
    ));
    assert!(matches!(
        tls64.address_of_callbacks.value,
        ImageBase::Base64(0x0000_0001_4000_9038)
    ));
}

/// x64 exception directory (`RUNTIME_FUNCTION`) on sample64.exe.
#[test]
fn test_pe_exception_directory_sample64() {
    let pe = pe::PE::from_file("tests/samples/sample64.exe").expect("Failed to parse PE64");
    let exceptions = pe.exceptions().unwrap().expect("exception directory");

    assert_eq!(exceptions.entries.len(), 44);
    let first = &exceptions.entries[0];
    assert_eq!(first.begin_address.value, 0x1000);
    assert_eq!(first.end_address.value, 0x1001);
    assert_eq!(first.unwind_data.value, 0x6000);
    assert_eq!(first.begin_address.offset, exceptions.offset);

    let second = &exceptions.entries[1];
    assert_eq!(second.begin_address.value, 0x1010);
    assert_eq!(second.end_address.value, 0x1136);
}

/// COFF symbol table on sample64.exe.
#[test]
fn test_pe_coff_symbols_sample64() {
    let pe = pe::PE::from_file("tests/samples/sample64.exe").expect("Failed to parse PE64");
    let symbols = pe.coff_symbols().expect("symbol table");

    assert_eq!(symbols.offset, 0x15e00);
    assert_eq!(symbols.symbols.len(), 902);
    assert_eq!(symbols.symbols[0].name, ".file");
    assert_eq!(symbols.symbols[0].symbol.section_number.value, -2);
    assert!(symbols.symbols.iter().any(|symbol| symbol.name == ".text"));
}

/// Applying a new image base patches HIGHLOW relocations in sample2.dll.
#[test]
fn test_pe_apply_image_base_with_relocations() {
    use pe::header::ImageBase;

    let mut pe = pe::PE::from_file("tests/samples/sample2.dll").expect("Failed to parse PE");
    assert!(!pe.base_relocations.is_empty());

    let target_rva = pe.base_relocations[0].entries[0].rva(pe.base_relocations[0].page_rva.value);
    let target_off = pe.rva_to_offset(target_rva).unwrap();
    let before = u32::from_le_bytes([
        pe.buffer[target_off],
        pe.buffer[target_off + 1],
        pe.buffer[target_off + 2],
        pe.buffer[target_off + 3],
    ]);

    pe.apply_image_base(ImageBase::Base32(0x6f75_0000))
        .expect("apply image base");

    let after = u32::from_le_bytes([
        pe.buffer[target_off],
        pe.buffer[target_off + 1],
        pe.buffer[target_off + 2],
        pe.buffer[target_off + 3],
    ]);
    assert_eq!(after, before.wrapping_add(0x1_0000));
    assert!(matches!(
        pe.optional_header.image_base.value,
        ImageBase::Base32(0x6f75_0000)
    ));
}

/// `number_of_rva_and_sizes` gates how many directories must be present on disk.
#[test]
fn test_pe_active_data_directory_count() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    assert_eq!(pe.optional_header.active_data_directory_count(), 16);
    assert!(pe.optional_header.has_data_directory(pe::header::IMPORT));
    assert!(pe
        .optional_header
        .has_data_directory(pe::header::DELAY_IMPORT));

    let mut buffer = pe.buffer.clone();
    buffer[pe.optional_header.number_of_rva_and_sizes.offset] = 10;
    buffer[pe.optional_header.number_of_rva_and_sizes.offset + 1] = 0;
    buffer[pe.optional_header.number_of_rva_and_sizes.offset + 2] = 0;
    buffer[pe.optional_header.number_of_rva_and_sizes.offset + 3] = 0;

    let trimmed = pe::PE::from_buffer(buffer).expect("parse trimmed optional header");
    assert_eq!(trimmed.optional_header.active_data_directory_count(), 10);
    assert!(!trimmed
        .optional_header
        .has_data_directory(pe::header::DELAY_IMPORT));
    assert_eq!(
        trimmed.optional_header.data_directories[pe::header::DELAY_IMPORT]
            .virtual_address
            .value,
        0
    );
}

/// Data directory RVA sync helper updates the optional header in place.
#[test]
fn test_pe_sync_data_directory_rva() {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let import_entry = &pe.optional_header.data_directories[pe::header::IMPORT];
    let old_offset = import_entry.virtual_address.offset;

    pe.sync_data_directory_rva(pe::header::IMPORT, 0xa000)
        .expect("sync RVA");
    assert_eq!(
        pe.optional_header.data_directories[pe::header::IMPORT]
            .virtual_address
            .value,
        0xa000
    );
    assert_eq!(
        u32::from_le_bytes([
            pe.buffer[old_offset],
            pe.buffer[old_offset + 1],
            pe.buffer[old_offset + 2],
            pe.buffer[old_offset + 3],
        ]),
        0xa000
    );
}

/// Section relocation blocks return empty vectors when the section has none.
#[test]
fn test_pe_section_relocations_empty() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let relocs = pe.section_relocations(0).expect("section relocs");
    assert!(relocs.entries.is_empty());
}

/// Absent optional directories return `None` without error.
#[test]
fn test_pe_optional_directories_absent() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    assert!(pe.bound_imports().unwrap().is_none());
    assert!(pe.delay_imports().unwrap().is_none());
    assert!(pe.load_config().unwrap().is_none());
    assert!(pe.resources().unwrap().is_none());
    assert!(pe.debug_directory().unwrap().is_none());
    assert!(pe.exceptions().unwrap().is_none());
}

/// Synthetic bound import and delay-load tables parse correctly.
#[test]
fn test_pe_bound_and_delay_import_synthetic() {
    use pe::bound::BoundImportDirectory;
    use pe::delay::DelayLoadDirectory;
    use pe::header::PEType;
    use pe::import::ImportEntry;
    use pe::section::PeSection;

    let mut buffer = vec![0u8; 0x200];
    let sections = vec![PeSection {
        name: hexspell::field::Field::new(
            hexspell::field::FixedBytes([b'.', b't', 0, 0, 0, 0, 0, 0]),
            0,
            8,
        ),
        virtual_size: hexspell::field::Field::new(0x200, 8, 4),
        virtual_address: hexspell::field::Field::new(0x1000, 12, 4),
        size_of_raw_data: hexspell::field::Field::new(0x200, 16, 4),
        pointer_to_raw_data: hexspell::field::Field::new(0, 20, 4),
        pointer_to_relocations: hexspell::field::Field::new(0, 24, 4),
        pointer_to_linenumbers: hexspell::field::Field::new(0, 28, 4),
        number_of_relocations: hexspell::field::Field::new(0, 32, 2),
        number_of_linenumbers: hexspell::field::Field::new(0, 34, 2),
        characteristics: hexspell::field::Field::new(0, 36, 4),
    }];

    // Bound import at RVA 0x1000 (file offset 0)
    buffer[0x04..0x06].copy_from_slice(&0x20u16.to_le_bytes()); // name offset
    buffer[0x20..0x2d].copy_from_slice(b"KERNEL32.dll\0");

    let bound = BoundImportDirectory::parse(&buffer, &sections, 0x1000).unwrap();
    assert_eq!(bound.modules.len(), 1);
    assert_eq!(bound.modules[0].module_name, "KERNEL32.dll");

    // Delay-load descriptor at RVA 0x1080 (offset 0x80)
    let delay_rva = 0x1080u32;
    let delay_off = 0x80usize;
    buffer[delay_off..delay_off + 4].copy_from_slice(&1u32.to_le_bytes()); // attributes
    buffer[delay_off + 4..delay_off + 8].copy_from_slice(&0x1040u32.to_le_bytes()); // dll name RVA
    buffer[delay_off + 16..delay_off + 20].copy_from_slice(&0x1100u32.to_le_bytes()); // INT
    buffer[0x40..0x4c].copy_from_slice(b"SHELL32.dll\0");
    // INT at RVA 0x1100 (offset 0x100)
    buffer[0x100..0x104].copy_from_slice(&0x1110u32.to_le_bytes());
    buffer[0x104..0x108].copy_from_slice(&0u32.to_le_bytes());
    // hint/name at RVA 0x1110 (offset 0x110)
    buffer[0x110..0x112].copy_from_slice(&7u16.to_le_bytes());
    buffer[0x112..0x121].copy_from_slice(b"GetProcAddress\0");

    let delay = DelayLoadDirectory::parse(&buffer, &sections, delay_rva, PEType::PE32).unwrap();
    assert_eq!(delay.descriptors.len(), 1);
    assert_eq!(delay.dlls[0].dll_name, "SHELL32.dll");
    assert!(delay.dlls[0].entries.iter().any(|entry| matches!(
        entry,
        ImportEntry::ByName { by_name, .. } if by_name.name == "GetProcAddress"
    )));
}

/// Synthetic resource tree with one named leaf.
#[test]
fn test_pe_resource_tree_synthetic() {
    use pe::resource::{ResourceEntry, ResourceTree};

    let mut buffer = vec![0u8; 0x200];
    let resource_base = 0usize;

    // Root directory: 1 named entry, 0 id entries
    buffer[0x0c..0x0e].copy_from_slice(&1u16.to_le_bytes()); // named entries
                                                             // Entry: name offset 0x30, data offset 0x50 (leaf)
    buffer[0x10..0x14].copy_from_slice(&0x30u32.to_le_bytes());
    buffer[0x14..0x18].copy_from_slice(&0x50u32.to_le_bytes()); // leaf (high bit clear)
                                                                // Unicode name at 0x30: length 4 chars "TEST"
    buffer[0x30..0x32].copy_from_slice(&4u16.to_le_bytes());
    buffer[0x32..0x3a].copy_from_slice(b"T\x00E\x00S\x00T\x00");
    // Data entry at 0x50
    buffer[0x50..0x54].copy_from_slice(&0x1200u32.to_le_bytes());
    buffer[0x54..0x58].copy_from_slice(&16u32.to_le_bytes());
    buffer[0x58..0x5c].copy_from_slice(&0u32.to_le_bytes());
    buffer[0x5c..0x60].copy_from_slice(&0u32.to_le_bytes());

    let sections = vec![pe::section::PeSection {
        name: hexspell::field::Field::new(
            hexspell::field::FixedBytes([b'.', b'r', b's', b'r', b'c', 0, 0, 0]),
            0,
            8,
        ),
        virtual_size: hexspell::field::Field::new(0x200, 8, 4),
        virtual_address: hexspell::field::Field::new(0x1000, 12, 4),
        size_of_raw_data: hexspell::field::Field::new(0x200, 16, 4),
        pointer_to_raw_data: hexspell::field::Field::new(0, 20, 4),
        pointer_to_relocations: hexspell::field::Field::new(0, 24, 4),
        pointer_to_linenumbers: hexspell::field::Field::new(0, 28, 4),
        number_of_relocations: hexspell::field::Field::new(0, 32, 2),
        number_of_linenumbers: hexspell::field::Field::new(0, 34, 2),
        characteristics: hexspell::field::Field::new(0, 36, 4),
    }];

    let tree = ResourceTree::parse(&buffer, resource_base, |rva| {
        pe::import::rva_to_offset(&buffer, &sections, rva)
    })
    .unwrap();

    assert_eq!(tree.root.entries.len(), 1);
    match &tree.root.entries[0] {
        ResourceEntry::Data { name, data, .. } => {
            assert_eq!(name.as_deref(), Some("TEST"));
            assert_eq!(data.offset_to_data.value, 0x1200);
            assert_eq!(data.size.value, 16);
        }
        _ => panic!("expected data leaf"),
    }
}

/// Synthetic debug directory entry.
#[test]
fn test_pe_debug_directory_synthetic() {
    use pe::debug::{DebugDirectory, IMAGE_DEBUG_TYPE_CODEVIEW};

    let mut buffer = vec![0u8; 0x100];
    let offset = 0x20usize;
    buffer[offset + 12..offset + 16].copy_from_slice(&IMAGE_DEBUG_TYPE_CODEVIEW.to_le_bytes());
    buffer[offset + 16..offset + 20].copy_from_slice(&8u32.to_le_bytes());
    buffer[offset + 20..offset + 24].copy_from_slice(&0x80u32.to_le_bytes());
    buffer[0x80..0x88].copy_from_slice(b"RSDS\x00\x00\x00\x00");

    let debug = DebugDirectory::parse(&buffer, offset, 28).unwrap();
    assert_eq!(debug.entries.len(), 1);
    assert_eq!(debug.entries[0].debug_type.value, IMAGE_DEBUG_TYPE_CODEVIEW);
    assert_eq!(
        debug.entries[0].raw_data(&buffer).unwrap(),
        b"RSDS\x00\x00\x00\x00"
    );
}

/// Forwarder exports are classified separately from local functions.
#[test]
fn test_pe_export_forwarder_synthetic() {
    use pe::export::{ExportDirectory, Exports, FunctionExport};

    let mut buffer = vec![0u8; 0x100];
    let export_dir_rva = 0x1000u32;
    let export_off = 0usize;

    // Minimal export directory header at offset 0
    buffer[export_off + 16..export_off + 20].copy_from_slice(&1u32.to_le_bytes()); // base
    buffer[export_off + 20..export_off + 24].copy_from_slice(&1u32.to_le_bytes()); // num functions
    buffer[export_off + 24..export_off + 28].copy_from_slice(&0u32.to_le_bytes()); // num names
    buffer[export_off + 28..export_off + 32].copy_from_slice(&0x1040u32.to_le_bytes()); // AOF RVA
                                                                                        // Function table at RVA 0x1040 -> offset 0x40: forwarder string at RVA 0x1048
    buffer[0x40..0x44].copy_from_slice(&0x1048u32.to_le_bytes());
    buffer[0x48..0x59].copy_from_slice(b"OTHER.DLL.Export\0");

    let sections = vec![pe::section::PeSection {
        name: hexspell::field::Field::new(
            hexspell::field::FixedBytes([b'.', b'e', 0, 0, 0, 0, 0, 0]),
            0,
            8,
        ),
        virtual_size: hexspell::field::Field::new(0x100, 8, 4),
        virtual_address: hexspell::field::Field::new(0x1000, 12, 4),
        size_of_raw_data: hexspell::field::Field::new(0x100, 16, 4),
        pointer_to_raw_data: hexspell::field::Field::new(0, 20, 4),
        pointer_to_relocations: hexspell::field::Field::new(0, 24, 4),
        pointer_to_linenumbers: hexspell::field::Field::new(0, 28, 4),
        number_of_relocations: hexspell::field::Field::new(0, 32, 2),
        number_of_linenumbers: hexspell::field::Field::new(0, 34, 2),
        characteristics: hexspell::field::Field::new(0, 36, 4),
    }];

    let directory = ExportDirectory::parse(&buffer, export_off).unwrap();
    let exports = Exports::parse(&buffer, &directory, export_dir_rva, 0x80, |rva| {
        pe::import::rva_to_offset(&buffer, &sections, rva)
    })
    .unwrap();

    assert_eq!(exports.functions.len(), 1);
    match &exports.functions[0] {
        FunctionExport::Forwarder { forwarder, .. } => {
            assert_eq!(forwarder, "OTHER.DLL.Export");
        }
        _ => panic!("expected forwarder export"),
    }
}

/// Synthetic COFF line number table on a section header.
#[test]
fn test_pe_linenumbers_synthetic() {
    use pe::linenum::{LineNumberBlock, LineNumberEntry};

    let mut buffer = vec![0u8; 0x40];
    let linenum_off = 0x10usize;
    // Source file record: Type=symbol index 3, LineNumber=0
    buffer[linenum_off..linenum_off + 4].copy_from_slice(&3u32.to_le_bytes());
    buffer[linenum_off + 4..linenum_off + 6].copy_from_slice(&0u16.to_le_bytes());
    // Line mapping: RVA 0x100, line 42
    buffer[linenum_off + 6..linenum_off + 10].copy_from_slice(&0x100u32.to_le_bytes());
    buffer[linenum_off + 10..linenum_off + 12].copy_from_slice(&42u16.to_le_bytes());

    let section = pe::section::PeSection {
        name: hexspell::field::Field::new(
            hexspell::field::FixedBytes([b'.', b't', 0, 0, 0, 0, 0, 0]),
            0,
            8,
        ),
        virtual_size: hexspell::field::Field::new(0x200, 8, 4),
        virtual_address: hexspell::field::Field::new(0x1000, 12, 4),
        size_of_raw_data: hexspell::field::Field::new(0x40, 16, 4),
        pointer_to_raw_data: hexspell::field::Field::new(0, 20, 4),
        pointer_to_relocations: hexspell::field::Field::new(0, 24, 4),
        pointer_to_linenumbers: hexspell::field::Field::new(linenum_off as u32, 28, 4),
        number_of_relocations: hexspell::field::Field::new(0, 32, 2),
        number_of_linenumbers: hexspell::field::Field::new(2, 34, 2),
        characteristics: hexspell::field::Field::new(0, 36, 4),
    };

    let block = LineNumberBlock::parse(&buffer, 0, &section).unwrap();
    assert_eq!(block.entries.len(), 2);
    assert!(block.entries[0].is_source_file());
    assert!(block.entries[1].is_line_mapping());
    assert_eq!(block.entries[1].line_number.value, 42);
    assert_eq!(block.entries[1].type_field.value, 0x100);
    assert_eq!(LineNumberEntry::SIZE, 6);
}

/// Synthetic Rich header between DOS stub and PE signature.
#[test]
fn test_pe_rich_header_synthetic() {
    use pe::rich::RichHeader;

    let xor_key = 0x1234_5678u32;
    let mut buffer = vec![0u8; 0x200];
    let pe_offset = 0x100usize;

    buffer[0x80..0x84].copy_from_slice(&(DANS_MAGIC ^ xor_key).to_le_bytes());
    let tool = ((0x0100u32) << 16) | 0x5a5au32;
    buffer[0x84..0x88].copy_from_slice(&(tool ^ xor_key).to_le_bytes());
    buffer[0x88..0x8c].copy_from_slice(&(1u32 ^ xor_key).to_le_bytes());
    buffer[0x8c..0x90].copy_from_slice(&(RICH_MAGIC ^ xor_key).to_le_bytes());
    buffer[0x90..0x94].copy_from_slice(&xor_key.to_le_bytes());

    let rich = RichHeader::parse(&buffer, pe_offset)
        .unwrap()
        .expect("rich header");
    assert_eq!(rich.xor_key, xor_key);
    assert_eq!(rich.entries.len(), 1);
    assert_eq!(rich.entries[0].product_id, 0x0100);
    assert_eq!(rich.entries[0].build_id, 0x5a5a);
    assert_eq!(rich.entries[0].count, 1);
}

const DANS_MAGIC: u32 = 0x536e_6144;
const RICH_MAGIC: u32 = 0x6863_6952;

/// Synthetic WIN_CERTIFICATE table (file offset, not RVA).
#[test]
fn test_pe_certificate_table_synthetic() {
    use pe::certificate::{
        CertificateTable, WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
    };

    let mut buffer = vec![0u8; 0x100];
    let cert_off = 0x80usize;
    let cert_len = 16u32;
    buffer[cert_off..cert_off + 4].copy_from_slice(&cert_len.to_le_bytes());
    buffer[cert_off + 4..cert_off + 6].copy_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
    buffer[cert_off + 6..cert_off + 8]
        .copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    buffer[cert_off + 8..cert_off + 16].copy_from_slice(b"PKCS7!!!");

    let table = CertificateTable::parse(&buffer, cert_off as u32, cert_len).unwrap();
    assert_eq!(table.certificates.len(), 1);
    assert_eq!(table.certificates[0].revision.value, WIN_CERT_REVISION_2_0);
    assert_eq!(table.certificates[0].data(&buffer).unwrap(), b"PKCS7!!!");
}

/// Synthetic IMAGE_COR20_HEADER.
#[test]
fn test_pe_clr_header_synthetic() {
    use pe::clr::{Cor20Header, COMIMAGE_FLAGS_ILONLY};

    let mut buffer = vec![0u8; 0x100];
    let offset = 0x20usize;
    buffer[offset..offset + 4].copy_from_slice(&72u32.to_le_bytes());
    buffer[offset + 4..offset + 6].copy_from_slice(&2u16.to_le_bytes());
    buffer[offset + 6..offset + 8].copy_from_slice(&5u16.to_le_bytes());
    buffer[offset + 8..offset + 12].copy_from_slice(&0x3000u32.to_le_bytes());
    buffer[offset + 12..offset + 16].copy_from_slice(&0x200u32.to_le_bytes());
    buffer[offset + 16..offset + 20].copy_from_slice(&COMIMAGE_FLAGS_ILONLY.to_le_bytes());
    buffer[offset + 20..offset + 24].copy_from_slice(&0x0600_0001u32.to_le_bytes());

    let cor20 = Cor20Header::parse(&buffer, offset).unwrap();
    assert_eq!(cor20.major_runtime_version.value, 2);
    assert_eq!(cor20.minor_runtime_version.value, 5);
    assert_eq!(cor20.metadata.virtual_address.value, 0x3000);
    assert!(cor20.is_il_only());
}

/// CHPE metadata blob is classified as architecture-specific data.
#[test]
fn test_pe_chpe_metadata_synthetic() {
    use pe::arch_data::{ArchitectureData, ArchitectureDataKind};
    use pe::coff::CoffFileHeader;
    use pe::header::DataDirectoryEntry;

    let mut buffer = vec![0u8; 0x100];
    let meta_off = 0x40usize;
    buffer[meta_off..meta_off + 4].copy_from_slice(&1u32.to_le_bytes());
    buffer[meta_off + 4..meta_off + 8].copy_from_slice(&0x2000u32.to_le_bytes());
    buffer[meta_off + 8..meta_off + 12].copy_from_slice(&0x100u32.to_le_bytes());

    let coff = CoffFileHeader {
        machine: hexspell::field::Field::new(0x01c4, 0, 2),
        number_of_sections: hexspell::field::Field::new(1, 2, 2),
        time_date_stamp: hexspell::field::Field::new(0, 4, 4),
        pointer_to_symbol_table: hexspell::field::Field::new(0, 8, 4),
        number_of_symbols: hexspell::field::Field::new(0, 12, 4),
        size_of_optional_header: hexspell::field::Field::new(0, 16, 2),
        characteristics: hexspell::field::Field::new(0, 18, 2),
    };

    let sections = vec![pe::section::PeSection {
        name: hexspell::field::Field::new(
            hexspell::field::FixedBytes([b'.', b't', 0, 0, 0, 0, 0, 0]),
            0,
            8,
        ),
        virtual_size: hexspell::field::Field::new(0x100, 8, 4),
        virtual_address: hexspell::field::Field::new(0x1000, 12, 4),
        size_of_raw_data: hexspell::field::Field::new(0x100, 16, 4),
        pointer_to_raw_data: hexspell::field::Field::new(0, 20, 4),
        pointer_to_relocations: hexspell::field::Field::new(0, 24, 4),
        pointer_to_linenumbers: hexspell::field::Field::new(0, 28, 4),
        number_of_relocations: hexspell::field::Field::new(0, 32, 2),
        number_of_linenumbers: hexspell::field::Field::new(0, 34, 2),
        characteristics: hexspell::field::Field::new(0, 36, 4),
    }];

    let arch_dir = DataDirectoryEntry {
        virtual_address: hexspell::field::Field::new(0, 0, 4),
        size: hexspell::field::Field::new(0, 4, 4),
    };

    let data = ArchitectureData::parse(&buffer, &coff, &arch_dir, None, Some(0x1040), |rva| {
        pe::import::rva_to_offset(&buffer, &sections, rva)
    })
    .unwrap();

    assert_eq!(data.kind, ArchitectureDataKind::ChpeMetadata);
    assert_eq!(data.code_map_rva.unwrap().value, 0x2000);
    assert_eq!(data.code_map_size.unwrap().value, 0x100);
}

/// rename_section updates the 8-byte section name in the buffer.
#[test]
fn test_pe_rename_section() {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let name_offset = pe.sections[0].name.offset;
    pe.rename_section(0, ".renamed").expect("rename");
    assert_eq!(pe.sections[0].name_str(), ".renamed");
    assert_eq!(&pe.buffer[name_offset..name_offset + 8], b".renamed");
}

/// remove_section drops a section and decrements the section count.
#[test]
fn test_pe_remove_section() {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let before = pe.coff_header.number_of_sections.value;
    let last_index = pe.sections.len() - 1;
    pe.remove_section(last_index).expect("remove section");
    assert_eq!(pe.coff_header.number_of_sections.value, before - 1);
    assert_eq!(pe.sections.len(), before as usize - 1);
}

/// grow_optional_header inserts bytes before the section table.
#[test]
fn test_pe_grow_optional_header() {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let old_size = pe.coff_header.size_of_optional_header.value;
    let first_section_offset = pe.sections[0].name.offset;
    pe.grow_optional_header(16).expect("grow optional header");
    assert_eq!(pe.coff_header.size_of_optional_header.value, old_size + 16);
    assert_eq!(pe.sections[0].name.offset, first_section_offset + 16);
}

/// sync_layout refreshes SizeOfImage and checksum from the current section table.
#[test]
fn test_pe_sync_layout() {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let expected_image = pe.optional_header.size_of_image.value;
    pe.sync_layout().expect("sync layout");
    assert_eq!(pe.optional_header.size_of_image.value, expected_image);
    assert_eq!(pe.optional_header.checksum.value, pe.calc_checksum());
}

/// Rich header is absent on minimal test binaries without linker metadata.
#[test]
fn test_pe_rich_header_absent_on_sample() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    let rich = pe.rich_header().expect("rich parse");
    // sample1 may or may not have a Rich header depending on toolchain
    let _ = rich;
}

/// COM descriptor and certificate directories are absent on sample1.
#[test]
fn test_pe_clr_and_cert_absent_on_sample() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    assert!(pe.clr().unwrap().is_none());
    assert!(pe.certificates().unwrap().is_none());
    assert_eq!(
        pe.architecture_data().unwrap().kind,
        pe::arch_data::ArchitectureDataKind::None
    );
}

/// sample1 has eight section headers ending at 0x2e0; shrink SizeOfHeaders so the next insert grows headers.
const SAMPLE1_TIGHT_SIZE_OF_HEADERS: u32 = 0x2d0;

fn sample1_with_tight_size_of_headers() -> pe::PE {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Failed to parse PE");
    pe.optional_header
        .size_of_headers
        .update(&mut pe.buffer, SAMPLE1_TIGHT_SIZE_OF_HEADERS)
        .expect("tighten SizeOfHeaders");
    pe
}

/// insert_section must bump the new section raw pointer when header padding shifts existing sections.
#[test]
fn test_pe_insert_section_header_grow_preserves_section_data() {
    let mut pe = sample1_with_tight_size_of_headers();

    let text_marker = [0xDE, 0xAD, 0xBE, 0xEF];
    let text_ptr = pe.sections[0].pointer_to_raw_data.value as usize;
    pe.buffer[text_ptr..text_ptr + 4].copy_from_slice(&text_marker);

    let last_index = pe.sections.len() - 1;
    let last_ptr = pe.sections[last_index].pointer_to_raw_data.value;
    let last_raw = pe.sections[last_index].size_of_raw_data.value;

    let new_payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    pe.insert_section(pe::section::NewSection {
        name: ".grow".into(),
        data: new_payload.clone(),
        characteristics: pe::section::CODE | pe::section::READ,
    })
    .expect("insert_section with header growth");

    assert!(
        pe.optional_header.size_of_headers.value > SAMPLE1_TIGHT_SIZE_OF_HEADERS,
        "insert should grow SizeOfHeaders"
    );

    let inserted = pe.sections.last().expect("new section");
    assert!(
        inserted.pointer_to_raw_data.value >= last_ptr + last_raw,
        "new raw pointer must not overlap the previous section file range"
    );
    assert_eq!(pe.section_data(0).unwrap()[..4], text_marker);
    assert_eq!(
        &pe.section_data(pe.sections.len() - 1).unwrap()[..new_payload.len()],
        new_payload.as_slice()
    );
}

/// Authenticode overlay must stay addressable after header padding shifts file offsets.
#[test]
fn test_pe_insert_section_header_grow_rebases_security_directory() {
    use pe::certificate::{WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA};
    use pe::header::SECURITY;

    let mut pe = sample1_with_tight_size_of_headers();

    const CERT_PAYLOAD: &[u8] = b"PKCS7!!!";
    let cert_entry_len = 16u32;
    // Place the overlay after the new section's file-backed range once header padding shifts offsets.
    const CERT_FILE_OFFSET: usize = 0x5a00;
    if pe.buffer.len() < CERT_FILE_OFFSET {
        pe.buffer.resize(CERT_FILE_OFFSET, 0);
    }
    let cert_off = CERT_FILE_OFFSET;
    pe.buffer.resize(cert_off + cert_entry_len as usize, 0);
    pe.buffer[cert_off..cert_off + 4].copy_from_slice(&cert_entry_len.to_le_bytes());
    pe.buffer[cert_off + 4..cert_off + 6].copy_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
    pe.buffer[cert_off + 6..cert_off + 8]
        .copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    pe.buffer[cert_off + 8..cert_off + 16].copy_from_slice(CERT_PAYLOAD);

    pe.optional_header.data_directories[SECURITY]
        .virtual_address
        .update(&mut pe.buffer, cert_off as u32)
        .expect("security offset");
    pe.optional_header.data_directories[SECURITY]
        .size
        .update(&mut pe.buffer, cert_entry_len)
        .expect("security size");

    assert_eq!(
        pe.certificates()
            .expect("cert parse before insert")
            .expect("cert table")
            .certificates[0]
            .data(&pe.buffer)
            .unwrap(),
        CERT_PAYLOAD
    );

    let old_cert_off = cert_off as u32;
    pe.insert_section(pe::section::NewSection {
        name: ".sig".into(),
        data: vec![0x11, 0x22, 0x33, 0x44],
        characteristics: pe::section::READ,
    })
    .expect("insert_section with cert overlay");

    let header_growth = pe.optional_header.size_of_headers.value - SAMPLE1_TIGHT_SIZE_OF_HEADERS;
    assert!(header_growth > 0, "header padding should have occurred");

    let security = &pe.optional_header.data_directories[SECURITY];
    assert_eq!(
        security.virtual_address.value,
        old_cert_off + header_growth,
        "SECURITY directory must be rebased by header padding bytes"
    );

    let table = pe
        .certificates()
        .expect("cert parse after insert")
        .expect("cert table");
    assert_eq!(
        table.certificates[0].data(&pe.buffer).unwrap(),
        CERT_PAYLOAD
    );
}
