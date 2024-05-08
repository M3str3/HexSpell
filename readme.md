# HexSpell: The Executable Rust Parser
## Description
HexSpell is an open source library 
created in Rust, designed to parse and manipulate executable files (.exe, .dll, etc.) with minimal dependencies. The reason for this library is to deepen my knowledge about executables, their manipulation and Rust! 

<p align="center">
<img src="https://github.com/M3str3/HexSpell/assets/62236987/8d5d500a-acb1-45d0-a63e-ec610b5e5ccc" width=50% height=50% style="display: block; margin: 0 auto">
</p>

## Example

### To add HexSpell
To include HexSpell in your Rust project, add it to your dependencies:
`cargo add hex_spell`

### Modify attributes from PE file
Using HexSpell to change the entry point of a PE file:
```rust
use hex_spell::pe_file;

fn main() {
    // Attempt to parse a PE from file  
    let mut pe = match pe_file::parse_from_file("file.exe") {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to parse PE file: {}", e);
            return;
        }
    };

    // Print old entry point
    print!("Old entry point: {:X} | ", pe.entry_point.value);

    // Update the entry point to a new value, on the same pe.buffer
    pe.entry_point.update(&mut pe.buffer, 0x36D4u32);

    // Print new entry point
    print!("New entry point: {:X}", pe.entry_point.value);

    // Try to write the modified PE file back to disk
    if let Err(e) = pe.write_file("file_modified.exe") {
        eprintln!("Failed to write modified PE file: {}", e);
    }
}
```
