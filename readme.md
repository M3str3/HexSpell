# HexSpell: The Executable Rust Parser
## Description
HexSpell is an open source library 
created in Rust, designed to parse and manipulate executable files (.exe, .dll, etc.) with minimal dependencies. The reason for this library is to deepen my knowledge about executables, their manipulation and Rust! 

<p align="center">
<img src="https://github.com/M3str3/HexSpell/assets/62236987/8d5d500a-acb1-45d0-a63e-ec610b5e5ccc" width=50% height=50% style="display: block; margin: 0 auto">
</p>

## Features
- **Low Dependency:** Uses minimal external libraries for easy integration and maintenance
- **PE & ELF parse**: Understandable PE & ELF file struct 
- **Modify functions**: Functions to help manipulating executables


## Installation
To include HexSpell in your Rust project, add it to your dependencies with cargo:
```bash
cargo add hex_spell
```

or just add this line to your `Cargo.toml` 

```toml
[dependencies]
hex_spell = "0.1.x"
```
## Examples of use
Some examples of use
### Display PE info
Displaying info about a PE file
```rust
use hex_spell::pe::PE;

fn main() {
    let file_name = "outt.exe";
    let pe = PE::from_file(file_name).unwrap();
 
    println!("┌───────────────────────────────┐");
    println!("│ File {}\t\t\t│",                file_name);
    println!("│ File PE Checksum: 0x{:X}\t│",   pe.header.checksum.value);
    println!("│ Architecture: {}\t\t│",         pe.header.architecture.value);
    println!("│ PE type: {:?}\t\t\t│",          pe.header.pe_type);
    println!("│ Number of sections 0x{:X}\t│",  pe.header.number_of_sections.value);
    println!("│ Size of image: 0x{:X}\t\t│",    pe.header.size_of_image.value);
    println!("└───────────────────────────────┘");
}
```

### Modify attributes from PE file
Using HexSpell to change the entry point of a PE file:
```rust
use hex_spell::pe::PE;

fn main() {
    // Attempt to parse a PE from file  
    let mut pe = match PE::from_file("file.exe") {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to parse PE file: {}", e);
            return;
        }
    };

    // Print old entry point
    print!("Old entry point: {:X} | ", pe.header.entry_point.value);

    // Update the entry point to a new value, on the same pe.buffer
    pe.header.entry_point.update(&mut pe.buffer, 0x36D4u32);

    // Print new entry point
    print!("New entry point: {:X}", pe.header.entry_point.value);

    // Try to write the modified PE file back to disk
    if let Err(e) = pe.write_file("file_modified.exe") {
        eprintln!("Failed to write modified PE file: {}", e);
    }
}
```
### Changing .text section code
Writing a shellcode on .text section, generally the first section
```rust
use hex_spell::pe::PE;

const SHELLCODE: [u8; 284] = [../*msfvenom shellcode*/..]

fn main() {
    // Attempt to parse a PE from file 
    let mut pe = PE::from_file("file.exe").expect("Failed to parse file");

    // Section .text, generally the first one
    let text_offset = pe.sections[0].pointer_to_raw_data.value as usize;
    let text_size = pe.sections[0].size_of_raw_data.value as usize;

    // Preparing the shellcode to have the same size as the section
    let mut payload = vec![0; text_size];
    payload.splice(..SHELLCODE.len(), SHELLCODE.iter().cloned());
    // Updating section with the payload
    pe.buffer.splice(text_offset..text_offset + text_size, payload.iter().cloned());

    // Changing entry point && checksum
    pe.header.entry_point.update(&mut pe.buffer, text_offset as u32);
    let new_checksum = pe.calc_checksum();
    pe.header.checksum.update(&mut pe.buffer, new_checksum);

    // Writing the output
    pe.write_file("modified.exe").expect("Failed to write modified file");
}
``` 
## Support or Contact

Having trouble with HexSpell? Please [submit an issue](https://github.com/M3str3/HexSpell/issues) on GitHub.

## License

HexSpell is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
