use std::fs;
use toml::Value;

use hexspell::macho;

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
            if file_extension != "" {
                file_name += &format!(".{}", file_extension);
            }

            // Getting real values from test.toml
            let macho_file: macho::MachO = macho::MachO::from_file(&file_name).expect("Error parsing MachO file");
            
            let magic = value
                .get("magic")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();

            let cputype = value
                .get("cputype")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();

            let cpusubtype = value
                .get("cpusubtype")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();

            let filetype = value
                .get("filetype")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();

            let ncmds = value
                .get("ncmds")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();

            let sizeofcmds = value
                .get("sizeofcmds")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();

            let flags = value
                .get("flags")
                .and_then(|v| v.as_str())
                .map(|s| u32::from_str_radix(s, 16).unwrap())
                .unwrap();

            
            // Testing parse params result
            assert_eq!(macho_file.header.magic.value, magic, "macho_file.header.magic doesnt match");
            assert_eq!(macho_file.header.cpu_type.value, cputype, "macho_file.header.cpu_type doesnt match");
            assert_eq!(macho_file.header.cpu_subtype.value, cpusubtype, "macho_file.header.cpu_subtype doesnt match");
            assert_eq!(macho_file.header.file_type.value, filetype, "macho_file.header.file_type doesnt match");
            assert_eq!(macho_file.header.ncmds.value, ncmds, "macho_file.header.ncmds doesnt match");
            assert_eq!(macho_file.header.sizeofcmds.value, sizeofcmds, "macho_file.header.sizeofcmds doesnt match");
            assert_eq!(macho_file.header.flags.value, flags, "macho_file.header.flags doesnt match");
      
      
        }
    }
}
