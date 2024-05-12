use std::fs;
use toml::Value;

use hex_spell::pe::{self, PE };
use hex_spell::elf;

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
                .map(|s| u16::from_str_radix(s, 16).unwrap())
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
            assert_eq!(pe.header.architecture.value.to_string(), architecture, "Architecture does not match for {}",key);
            assert_eq!(pe.header.checksum.value, checksum, "Checksum does not match for {}",key);
            assert_eq!(pe.header.entry_point.value, entry_point, "Entry point does not match for {}", key);
            assert_eq!(pe.header.size_of_image.value, size_of_image,"Size of image does not match for {}",key);
            assert_eq!(pe.header.number_of_sections.value, number_of_sections, "Number of sections does not match for {}",key);
            assert_eq!(pe.header.section_alignment.value, section_alignment, "Section alignment of sections does not match for {}",key);
            assert_eq!(pe.header.file_alignment.value, file_alignment, "File alignment does not match for {}",key);
            assert_eq!(pe.header.base_of_code.value, base_of_code, "Base of code does not match for {}",key);
            assert_eq!(pe.header.base_of_data.value, base_of_data, "Base of data does not match for {}",key);
            assert_eq!(pe.header.size_of_headers.value, size_of_headers, "Size of headers does not match for {}",key);
            assert_eq!(pe.header.subsystem.value, subsystem, "Subsystem does not match for {}",key);
            assert_eq!(pe.header.dll_characteristics.value, dll_characteristics, "DLL characteristics does not match for {}",key);
            match pe.header.pe_type {
                pe::header::PEType::PE32 => {
                    let image_base = value
                        .get("image_base")
                        .and_then(|v| v.as_str())
                        .map(|s| u32::from_str_radix(s, 16).unwrap())
                        .unwrap();
                    match pe.header.image_base.value {
                        pe::header::ImageBase::Base32(base) => assert_eq!(base, image_base, "[PE32] Image base does not match for {}", key),
                            _ => panic!("Incorrect type for image_base, expected u32"),
                        }
                },
                pe::header::PEType::PE32Plus => {
                    let image_base = value
                        .get("image_base")
                        .and_then(|v| v.as_str())
                        .map(|s| u64::from_str_radix(s, 16).unwrap())
                        .unwrap();
                    match pe.header.image_base.value {
                        pe::header::ImageBase::Base64(base) => assert_eq!(base, image_base, "[PE32+] Image base does not match for {}", key),
                        _ => panic!("Incorrect type for image_base, expected u64"),
                    }
                }
            }

            // Testing some functions
            let checksum_calculed: u32 = pe.calc_checksum();
            assert_eq!(pe.header.checksum.value, checksum_calculed, "Calculed checksum doesnt fit the original checksum");
    
            // Updating params    
            let new_entry: u32 = 0x32EDu32;
            pe.header.entry_point.update(&mut pe.buffer, new_entry);
            assert_eq!(pe.header.entry_point.value, new_entry, "Entry point didnt changed");
    
            let new_section_name = String::from(".test");
            pe.sections[0].name.update(&mut pe.buffer, &new_section_name);
            assert_eq!(pe.sections[0].name.value, new_section_name, "Section name didnt changed");
        }
    }
}

#[test]
fn test_elf_parse() {
    let toml_contents: String = fs::read_to_string("tests/tests.toml").expect("Failed to read tests.toml");
    let data: Value = toml_contents.parse::<Value>().expect("Failed to parse TOML");

    // ELF FILES 
    if let Some(elf) = data.get("elf").and_then(|v| v.as_table()) {
        for (key, value) in elf {
            let file_extension: &str = value.get("file_extension").and_then(|v| v.as_str()).unwrap_or("");
            let mut file_name: String =  format!("tests/samples/{}", key);
            if file_extension != "" {
                file_name += &format!(".{}",file_extension);
            }
            let elf: elf::ELF = elf::ELF::from_file(&file_name).expect("HOLa");
            
            let e_version = value
                .get("e_version")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 10).unwrap())
                .unwrap();
            let e_entry = value
                .get("e_entry")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s, 16).unwrap())
                .unwrap();

            let e_phoff = value
                .get("e_phoff")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s, 10).unwrap())
                .unwrap();

            let e_shoff = value
                .get("e_shoff")
                .and_then(|v| v.as_str())
                .map(|s| u64::from_str_radix(s, 10).unwrap())
                .unwrap();

            let e_flags = value
                .get("e_flags")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 10).unwrap())
                .unwrap();

            let e_ehsize = value
                .get("e_ehsize")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 10).unwrap())
                .unwrap();

            let e_phentsize = value
                .get("e_phentsize")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 10).unwrap())
                .unwrap();

            let e_phnum = value
                .get("e_phnum")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 10).unwrap())
                .unwrap();

            let e_shentsize = value
                .get("e_shentsize")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 10).unwrap())
                .unwrap();

            let e_shnum = value
                .get("e_shnum")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 10).unwrap())
                .unwrap();


            let e_shstrndx = value
                .get("e_shstrndx")
                .and_then(|v| v.as_str())
                .map(|s| u16::from_str_radix(s, 10).unwrap())
                .unwrap();


            let program1_p_type = value
                .get("program1_p_type")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 10).unwrap())
                .unwrap();
            
            assert_eq!(elf.header.version.value, e_version, "header.version doesnt match");
            assert_eq!(elf.header.entry.value, e_entry, "header.entry doesnt match");
            assert_eq!(elf.header.ph_off.value, e_phoff, "header.ph_off doesnt match");
            assert_eq!(elf.header.sh_off.value, e_shoff, "header.hs_off doesnt match");
            assert_eq!(elf.header.flags.value, e_flags, "header.flags doesnt match");
            assert_eq!(elf.header.eh_size.value, e_ehsize, "header.sh_size doesnt match");
            assert_eq!(elf.header.ph_ent_size.value, e_phentsize, "header.ph_ent_size doesnt match");
            assert_eq!(elf.header.ph_num.value, e_phnum, "header.ph_num doesnt match");
            assert_eq!(elf.header.sh_ent_size.value, e_shentsize, "header.sh_ent_size doesnt match");
            assert_eq!(elf.header.sh_num.value, e_shnum, "header.sh_num doesnt match");
            assert_eq!(elf.header.sh_strndx.value, e_shstrndx, "header.sh_strndx doesnt match");
            assert_eq!(elf.program_headers[0].p_type.value, program1_p_type, "program header 0.p_type doesnt match");
    
    }
}
}