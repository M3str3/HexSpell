use std::fs;
use std::collections::HashMap;
use toml;  

use runic::pe_file::{ PeFile, parse_from_file };

#[test]
fn test_pe_parse() {
    // Read the TOML configuration to check if it is parsing correctly
    let toml_contents = fs::read_to_string("tests/tests.toml").expect("Failed to read test.toml");
    let test_cases: HashMap<String, HashMap<String, String>> = toml::from_str(&toml_contents).expect("Failed to parse TOML");

    for (key, value) in test_cases {
       
        let file_name: String = format!("tests/samples/{}.exe", key);
        let pe: PeFile = parse_from_file(file_name.as_str()).expect("Failed to parse PE");

        let architecture: String = String::from(value.get("architecture").unwrap());
        let checksum: u32 = u32::from_str_radix(value.get("checksum").unwrap().trim_start_matches("0x"), 16).unwrap();
        let entry_point: u32 = u32::from_str_radix(value.get("entry_point").unwrap().trim_start_matches("0x"), 16).unwrap();
        let size_of_image: u32 = u32::from_str_radix(value.get("size_of_image").unwrap().trim_start_matches("0x"), 16).unwrap();
        let number_of_sections: u32 = u32::from_str_radix(value.get("number_of_sections").unwrap().trim_start_matches("0x"), 16).unwrap();
        
        assert_eq!(pe.architecture, architecture, "Architecture does not match for {}",key);
        assert_eq!(pe.checksum, checksum, "Checksum does not match for {}",key);
        assert_eq!(pe.entry_point, entry_point, "Entry point does not match for {}", key);
        assert_eq!(pe.size_of_image, size_of_image,"Size of image does not match for {}",key);
        assert_eq!(pe.number_of_sections, number_of_sections, "Number of sections does not match for {}",key);
        
    }
}
