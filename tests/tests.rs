use std::fs;
use toml::Value;

use hex_spell::pe::{self, PE };

#[test]
fn test_pe_parse() {
    let toml_contents: String = fs::read_to_string("tests/tests.toml").expect("Failed to read tests.toml");
    let data: Value = toml_contents.parse::<Value>().expect("Failed to parse TOML");

    // PE FILES (pe, pe_section)
    if let Some(pe) = data.get("pe").and_then(|v| v.as_table()) {
        for (key, value) in pe {
            let file_extension: &str = value.get("file_extension").and_then(|v| v.as_str()).unwrap_or("exe");
            let file_name: String = format!("tests/samples/{}.{}", key, file_extension);
            let mut pe: PE = PE::parse_from_file(&file_name).expect("Failed to parse PE");
    
            // Getting real values from test.toml
            let architecture = value
                .get("architecture")
                .and_then(|v| v.as_str())
                .unwrap();
            let checksum = value
                .get("checksum")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let entry_point = value
                .get("entry_point")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let size_of_image = value
                .get("size_of_image")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let number_of_sections = value
                .get("number_of_sections")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let section_alignment = value
                .get("section_alignment")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let file_alignment = value
                .get("file_alignment")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let base_of_code = value
                .get("base_of_code")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let base_of_data = value
                .get("base_of_data")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let size_of_headers = value
                .get("size_of_headers")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();
            let subsystem = value
                .get("subsystem")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 16).unwrap())
                .unwrap();
            let dll_characteristics = value
                .get("dll_characteristics")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 16).unwrap())
                .unwrap();
            
            // Testing parse params result
            assert_eq!(pe.architecture.value.to_string(), architecture, "Architecture does not match for {}",key);
            assert_eq!(pe.checksum.value, checksum, "Checksum does not match for {}",key);
            assert_eq!(pe.entry_point.value, entry_point, "Entry point does not match for {}", key);
            assert_eq!(pe.size_of_image.value, size_of_image,"Size of image does not match for {}",key);
            assert_eq!(pe.number_of_sections.value, number_of_sections, "Number of sections does not match for {}",key);
            assert_eq!(pe.section_alignment.value, section_alignment, "Section alignment of sections does not match for {}",key);
            assert_eq!(pe.file_alignment.value, file_alignment, "File alignment does not match for {}",key);
            assert_eq!(pe.base_of_code.value, base_of_code, "Base of code does not match for {}",key);
            assert_eq!(pe.base_of_data.value, base_of_data, "Base of data does not match for {}",key);
            assert_eq!(pe.size_of_headers.value, size_of_headers, "Size of headers does not match for {}",key);
            assert_eq!(pe.subsystem.value, subsystem, "Subsystem does not match for {}",key);
            assert_eq!(pe.dll_characteristics.value, dll_characteristics, "DLL characteristics does not match for {}",key);
            match pe.pe_type {
                pe::PEType::PE32 => {
                    let image_base = value
                        .get("image_base")
                        .and_then(|v| v.as_str())
                        .map(|s| u32::from_str_radix(s, 16).unwrap())
                        .unwrap();
                    match pe.image_base.value {
                            pe::ImageBase::Base32(base) => assert_eq!(base, image_base, "[PE32] Image base does not match for {}", key),
                            _ => panic!("Incorrect type for image_base, expected u32"),
                        }
                },
                pe::PEType::PE32Plus => {
                    let image_base = value
                        .get("image_base")
                        .and_then(|v| v.as_str())
                        .map(|s| u64::from_str_radix(s, 16).unwrap())
                        .unwrap();
                    match pe.image_base.value {
                        pe::ImageBase::Base64(base) => assert_eq!(base, image_base, "[PE32+] Image base does not match for {}", key),
                        _ => panic!("Incorrect type for image_base, expected u64"),
                    }
                }
            }

            // Testing some functions
            let checksum_calculed: u32 = pe.calc_checksum();
            assert_eq!(pe.checksum.value, checksum_calculed, "Calculed checksum doesnt fit the original checksum");
    
            // Updating params    
            let new_entry: u32 = 0x32EDu32;
            pe.entry_point.update(&mut pe.buffer, new_entry);
            assert_eq!(pe.entry_point.value, new_entry, "Entry point didnt changed");
    
            let new_section_name = String::from(".test");
            pe.sections[0].name.update(&mut pe.buffer, &new_section_name);
            assert_eq!(pe.sections[0].name.value, new_section_name, "Section name didnt changed");
        }
    }
}