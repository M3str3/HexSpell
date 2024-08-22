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

            //TODO
            let macho_file: macho::MachO =
                macho::MachO::from_file(&file_name).expect("Error parsing MachO file");
            for seg in macho_file.segments {
                println!("{}", seg.name)
            }
        }
    }
}
