use std::fs;
use toml::Value;

use hexspell::elf;

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