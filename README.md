# HexSpell: The Executable Rust Parser
## Table of Contents
- [Description](#description)
- [Features](#features)
- [Installation](#installation)
- [Examples of use](#examples-of-use)
  - [Parsing PE Files](#parsing-pe-files)
  - [Parsing ELF Files](#parsing-elf-files)
  - [Parsing Mach-O Files](#parsing-mach-o-files)
  - [Modify PE Attributes](#modify-pe-attributes)
  - [Create new section and injecting a shellcode](#create-new-section-and-injecting-a-shellcode)
- [Support or Contact](#support-or-contact)
- [License](#license)
## Description
HexSpell is an open source library created in Rust, designed to parse and manipulate various types of executable files, including PE (Portable Executable), ELF (Executable and Linkable Format), and Mach-O binaries. The library is built without dependencies, with the aim of providing an easy-to-use and flexible tool for developers to analyse and modify executables.

<p align="center">
<img src="https://github.com/M3str3/HexSpell/assets/62236987/8d5d500a-acb1-45d0-a63e-ec610b5e5ccc" style="display: block;width:50%;height:50%; margin: 0 auto">
</p>

## Features
- **No Dependency:** The library is built entirely without dependencies, making it lightweight and easy to maintain. 
- **Multi-format Support:** Parses and manipulates PE (Windows), ELF (Linux), and Mach-O (macOS) formats, including FAT Mach-O binaries
- **Automatic Endianness Handling:** Detects and respects ELF and Mach-O endianness during parsing
- **Executable Manipulation:** Modify executable attributes such as entry points, inject sections, update headers, and write changes back to disk using `write_file`
- **Checksum Calculation:** Validate or update checksums of parsed files
- **Cross-platform Support:** Provides consistent parsing and manipulation tools across multiple platforms

## Installation
To include HexSpell in your Rust project, add it to your dependencies with Cargo:

```bash
cargo add hexspell
```

Or manually add this line to your `Cargo.toml`:

```toml
[dependencies]
hexspell = "0.1.x"
```
## Examples of use

### Parsing PE Files
HexSpell allows you to parse and display important information from PE files.
```rust
use hexspell::pe::PE;

fn main() {
    let file_name = "tests/samples/sample1.exe";
    let pe = PE::from_file(file_name).unwrap();

    println!("╔════════════════════════════════════════╗");
    println!("║ File: {:<33}║",                             file_name);
    println!("╠════════════════════════════════════════╣");
    println!("║ PE Checksum:          0x{:08X}       ║",    pe.header.checksum.value);
    println!("║ Architecture:         {:<17}║",             pe.header.architecture.value);
    println!("║ PE Type:              {:?}             ║",  pe.header.pe_type);
    println!("║ Number of sections:   0x{:08X}       ║",    pe.header.number_of_sections.value);
    println!("║ Size of image:        0x{:08X}       ║",    pe.header.size_of_image.value);
    println!("╚════════════════════════════════════════╝");
}
```
#### OUTPUT
```plain
╔════════════════════════════════════════╗
║ File: tests/samples/sample1.exe        ║
╠════════════════════════════════════════╣
║ PE Checksum:          0x00007106       ║
║ Architecture:         x86              ║
║ PE Type:              PE32             ║
║ Number of sections:   0x00000008       ║
║ Size of image:        0x0000C000       ║
╚════════════════════════════════════════╝
```
### Parsing ELF Files
You can also easily parse ELF binaries (Linux executables) with HexSpell.
```rust
use hexspell::elf::ELF;

fn main() {
    let file_name = "tests/samples/linux";
    let elf_file = ELF::from_file("tests/samples/linux").unwrap();

    println!("╔════════════════════════════════════════╗");
    println!("║ File: {:<33}║",                             file_name);
    println!("╠════════════════════════════════════════╣");
    println!("║ Entry point:          0x{:08X}       ║",    elf_file.header.entry.value);
    println!("║ Program headers:      {:<17}║",             elf_file.header.ph_num.value);
    println!("║ Section headers:      {:<17}║",             elf_file.header.sh_num.value);
    println!("║ Endianness:           {:?}             ║",  elf_file.header.endianness);
    println!("╚════════════════════════════════════════╝");
}
```
#### OUTPUT
```plain
╔════════════════════════════════════════╗
║ File: tests/samples/linux              ║
╠════════════════════════════════════════╣
║ Entry point:          0x00001060       ║
║ Program headers:      13               ║
║ Section headers:      31               ║
║ Endianness:           Little           ║
╚════════════════════════════════════════╝
```
### Parsing Mach-O Files
Mach-O files, commonly used in macOS, can also be parsed and inspected.
```rust
use hexspell::macho::MachO;

fn main() {
    let file_name = "tests/samples/machO-OSX-x86-ls";
    let macho_file = MachO::from_file(file_name).unwrap();

    println!("╔════════════════════════════════════════╗");
    println!("║ File: {:<33}║",                              file_name);
    println!("╠════════════════════════════════════════╣");
    println!("║ Number of load commands: {:<14}║",           macho_file.header.ncmds.value);
    println!("║ File type:               {:?}             ║", macho_file.header.file_type.value);
    println!("║ Endianness:              {:?}             ║", macho_file.header.endianness);
    println!("║ First segment name:      {:<14}║",           macho_file.segments[0].name);
    println!("╚════════════════════════════════════════╝");
}
```
#### OUTPUT
```plain
╔════════════════════════════════════════╗
║ File: tests/samples/machO-OSX-x86-ls   ║
╠════════════════════════════════════════╣
║ Number of load commands: 16            ║
║ File type:               2             ║
║ Endianness:              Little        ║
║ First segment name:      __PAGEZERO    ║
╚════════════════════════════════════════╝
```

### Modify PE Attributes
HexSpell provides utilities to modify executables, such as changing the entry point of a PE file.
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
    pe.header.entry_point.update(&mut pe.buffer, 0x36D4u32).unwrap();

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
    pe.header.entry_point.update(&mut pe.buffer, pe.sections.last().unwrap().virtual_address.value).unwrap();

    // Write output to a new file
    pe.write_file("tests/out/modified.exe").expect("[!] Error writing new PE to disk");
}
```

## Support or Contact

Having trouble with HexSpell? Please [submit an issue](https://github.com/M3str3/HexSpell/issues) on GitHub.

## License

HexSpell is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
