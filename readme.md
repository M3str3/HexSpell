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
cargo add hexspell
```

or just add this line to your `Cargo.toml` 

```toml
[dependencies]
hexspell = "0.1.x"
```
## Examples of use
Some examples of use
### Display PE info
Displaying info about a PE file
```rust
use hexspell::pe::PE;

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
use hexspell::pe::PE;

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

### Create new section and injecting a shellcode
Adding code in a section with its own header
```rust
use hexspell::pe::PE;

const SHELLCODE: [u8; 284] = [../*msfvenom shellcode*/..]

fn main(){
    // Open PE from file
    let mut pe = PE::from_file("tests/samples/sample1.exe").expect("[!] Error opening PE file");

    // Create new section header based on basic parameters
    let new_section_header = pe.generate_section_header(
        ".shell", // Name for the new section
        shellcode.len() as u32, // The size of the data it has to store
        section::Characteristics::Code.to_u32() // Basic characteristics for a shellcode
            + section::Characteristics::Readable.to_u32()
            + section::Characteristics::Executable.to_u32(),
    ).expect("[!] Error generating new section header");

    // Add new section header and payload into PE
    pe.add_section(new_section_header, shellcode.to_vec()).expect("[!] Error adding new section into PE");

    // Optional: Update entry point to execute our payload instead of the original code
    pe.header.entry_point.update(&mut pe.buffer, pe.sections.last().unwrap().virtual_address.value);

    // Write output to a new file
    pe.write_file("tests/out/modified.exe").expect("[!] Error writing new PE to disk");
}
```

## Support or Contact

Having trouble with HexSpell? Please [submit an issue](https://github.com/M3str3/HexSpell/issues) on GitHub.

## License

HexSpell is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
