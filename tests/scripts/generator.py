"""
Automated script to generate tests.toml from executable binaries in samples/ (or other folder)
"""
from datetime import datetime

import traceback
import argparse
import struct
import toml
import os

header = """
 /$$   /$$                      /$$$$$$                      /$$ /$$
| $$  | $$                     /$$__  $$                    | $$| $$
| $$  | $$  /$$$$$$  /$$   /$$| $$  \__/  /$$$$$$   /$$$$$$ | $$| $$
| $$$$$$$$ /$$__  $$|  $$ /$$/|  $$$$$$  /$$__  $$ /$$__  $$| $$| $$
| $$__  $$| $$$$$$$$ \  $$$$/  \____  $$| $$  \ $$| $$$$$$$$| $$| $$
| $$  | $$| $$_____/  >$$  $$  /$$  \ $$| $$  | $$| $$_____/| $$| $$
| $$  | $$|  $$$$$$$ /$$/\  $$|  $$$$$$/| $$$$$$$/|  $$$$$$$| $$| $$
|__/  |__/ \_______/|__/  \__/ \______/ | $$____/  \_______/|__/|__/
                                        | $$                        
                                        | $$                        
                                        |__/    

HexSpell asset generation tool for testing
=========================================================================="""

parser = argparse.ArgumentParser(description="Parse executable files and generate a TOML report.")
parser.add_argument('-d', '--debug', action='store_true', help='Enable verbose debug output.')
parser.add_argument('-i', '--input', default='samples', help='Directory containing files to analyze (default: "samples").')
parser.add_argument('-o', '--output', default='tests.toml', help='Output TOML file path (default: "tests.toml").')
args = parser.parse_args()

DEBUG = args.debug

def log_message(msg: str, msg_type: str = 'info') -> None:
    if not DEBUG and msg_type == 'debug':
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{msg_type.upper()}] {msg}")

def parse_pe(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        f.seek(60)
        pe_offset = struct.unpack("<I", f.read(4))[0]
        log_message(f"PE offset: {pe_offset}", "debug")

        f.seek(pe_offset)
        pe_signature = f.read(4)
        log_message(f"PE signature: {pe_signature}", "debug")

        if len(pe_signature) < 4 or pe_signature != b"PE\x00\x00":
            raise ValueError(f"Invalid PE signature: {pe_signature}")
        
        header_data = f.read(20)
        log_message(f"COFF Header Data: {header_data.hex()}", "debug")

        if len(header_data) < 20:
            raise ValueError(f"Expected 20 bytes for COFF header, but got {len(header_data)}")

        machine, number_of_sections, _, _, _, size_of_optional_header, _ = struct.unpack("<HHIIIHH", header_data)
        log_message(f"Machine: {machine}, Sections: {number_of_sections}, Optional Header Size: {size_of_optional_header}", "debug")

        architecture = "x86" if machine == 0x014c else "x64"
        log_message(f"Architecture: {architecture}", "debug")

        f.seek(pe_offset + 24)
        optional_header_magic = struct.unpack("<H", f.read(2))[0]
        log_message(f"Optional Header Magic: {hex(optional_header_magic)}", "debug")

        f.seek(pe_offset + 24 + 16)  # AddressOfEntryPoint
        entry_point = struct.unpack("<I", f.read(4))[0]
        log_message(f"Entry Point: {hex(entry_point)}", "debug")

        f.seek(pe_offset + 24 + 28)  # ImageBase
        image_base = struct.unpack("<I", f.read(4))[0]
        log_message(f"Image Base: {hex(image_base)}", "debug")

        f.seek(pe_offset + 24 + 56)  # SizeOfImage
        size_of_image = struct.unpack("<I", f.read(4))[0]
        log_message(f"Size of Image: {hex(size_of_image)}", "debug")

        f.seek(pe_offset + 24 + 68)  # Subsystem
        subsystem = struct.unpack("<H", f.read(2))[0]
        log_message(f"Subsystem: {hex(subsystem)}", "debug")

        f.seek(pe_offset + 24 + 70)  # DllCharacteristics
        dll_characteristics = struct.unpack("<H", f.read(2))[0]
        log_message(f"DLL Characteristics: {hex(dll_characteristics)}", "debug")

        f.seek(pe_offset + 24 + 32)  # SectionAlignment
        section_alignment = struct.unpack("<I", f.read(4))[0]
        log_message(f"Section Alignment: {hex(section_alignment)}", "debug")

        f.seek(pe_offset + 24 + 36)  # FileAlignment
        file_alignment = struct.unpack("<I", f.read(4))[0]
        log_message(f"File Alignment: {hex(file_alignment)}", "debug")

        f.seek(pe_offset + 24 + 20)  # BaseOfCode
        base_of_code = struct.unpack("<I", f.read(4))[0]
        log_message(f"Base of Code: {hex(base_of_code)}", "debug")

        f.seek(pe_offset + 24 + 24)  # BaseOfData
        base_of_data = struct.unpack("<I", f.read(4))[0]
        log_message(f"Base of Data: {hex(base_of_data)}", "debug")

        f.seek(pe_offset + 24 + 60)  # SizeOfHeaders
        size_of_headers = struct.unpack("<I", f.read(4))[0]
        log_message(f"Size of Headers: {hex(size_of_headers)}", "debug")

        f.seek(pe_offset + 24 + 64)  # Checksum
        checksum = struct.unpack("<I", f.read(4))[0]
        log_message(f"Checksum: {hex(checksum)}", "debug")

        log_message("All assertions passed!", "debug")

        return {
            "architecture": architecture,
            "checksum": hex(checksum),
            "entry_point": hex(entry_point),
            "size_of_image": hex(size_of_image),
            "number_of_sections": f"{number_of_sections:02X}",
            "section_alignment": hex(section_alignment),
            "file_alignment": hex(file_alignment),
            "base_of_code": hex(base_of_code),
            "base_of_data": hex(base_of_data),
            "image_base": hex(image_base),
            "size_of_headers": hex(size_of_headers),
            "subsystem": hex(subsystem),
            "dll_characteristics": hex(dll_characteristics),
        }
    
def parse_elf(file_path: str) -> dict:
    with open(file_path, 'rb') as f:
        buffer = f.read()

    def extract_u16_le(buffer, offset):
        return struct.unpack_from('<H', buffer, offset)[0]

    def extract_u32_le(buffer, offset):
        return struct.unpack_from('<I', buffer, offset)[0]

    def extract_u64_le(buffer, offset):
        return struct.unpack_from('<Q', buffer, offset)[0]

    ident = buffer[0:16].hex()
    elf_type = extract_u16_le(buffer, 16)
    machine = extract_u16_le(buffer, 18)
    version = extract_u32_le(buffer, 20)
    entry = extract_u64_le(buffer, 24)
    ph_off = extract_u64_le(buffer, 32)
    sh_off = extract_u64_le(buffer, 40)
    flags = extract_u32_le(buffer, 48)
    eh_size = extract_u16_le(buffer, 52)
    ph_ent_size = extract_u16_le(buffer, 54)
    ph_num = extract_u16_le(buffer, 56)
    sh_ent_size = extract_u16_le(buffer, 58)
    sh_num = extract_u16_le(buffer, 60)
    sh_strndx = extract_u16_le(buffer, 62)

    elf_data = {
        "ident": f"0x{ident}",
        "elf_type": f"0x{elf_type:x}",
        "e_machine": f"0x{machine:x}",
        "e_version": f"0x{version:x}",
        "e_entry": f"0x{entry:x}",
        "e_phoff": f"0x{ph_off:x}",
        "e_shoff": f"0x{sh_off:x}",
        "e_flags": f"0x{flags:x}",
        "e_ehsize": f"0x{eh_size:x}",
        "e_phentsize": f"0x{ph_ent_size:x}",
        "e_phnum": f"0x{ph_num:x}",
        "e_shentsize": f"0x{sh_ent_size:x}",
        "e_shnum": f"0x{sh_num:x}",
        "e_shstrndx": f"0x{sh_strndx:x}",
    }

    program_headers = []
    for i in range(min(2, ph_num)):
        base = ph_off + i * ph_ent_size
        p_type = extract_u32_le(buffer, base)
        p_flags = extract_u32_le(buffer, base + 4)
        p_offset = extract_u64_le(buffer, base + 8)
        p_vaddr = extract_u64_le(buffer, base + 16)
        p_paddr = extract_u64_le(buffer, base + 24)
        p_filesz = extract_u64_le(buffer, base + 32)
        p_memsz = extract_u64_le(buffer, base + 40)
        p_align = extract_u64_le(buffer, base + 48)

        program_headers.append({
            "p_type": f"0x{p_type:x}",
            "p_flags": f"0x{p_flags:x}",
            "p_offset": f"0x{p_offset:x}",
            "p_vaddr": f"0x{p_vaddr:x}",
            "p_paddr": f"0x{p_paddr:x}",
            "p_filesz": f"0x{p_filesz:x}",
            "p_memsz": f"0x{p_memsz:x}",
            "p_align": f"0x{p_align:x}",
        })

    for idx, ph in enumerate(program_headers, 1):
        elf_data.update({
            f"p{idx}_p_type": ph['p_type'],
            f"p{idx}_p_flags": ph['p_flags'],
            f"p{idx}_p_offset": ph['p_offset'],
            f"p{idx}_p_vaddr": ph['p_vaddr'],
            f"p{idx}_p_paddr": ph['p_paddr'],
            f"p{idx}_p_filesz": ph['p_filesz'],
            f"p{idx}_p_memsz": ph['p_memsz'],
            f"p{idx}_p_align": ph['p_align'],
        })

    section_headers = []
    for i in range(min(2, sh_num)):
        base = sh_off + i * sh_ent_size
        sh_name = extract_u32_le(buffer, base)
        sh_type = extract_u32_le(buffer, base + 4)
        sh_flags = extract_u64_le(buffer, base + 8)
        sh_addr = extract_u64_le(buffer, base + 16)
        sh_offset = extract_u64_le(buffer, base + 24)
        sh_size = extract_u64_le(buffer, base + 32)
        sh_link = extract_u32_le(buffer, base + 40)
        sh_info = extract_u32_le(buffer, base + 44)
        sh_addralign = extract_u64_le(buffer, base + 48)
        sh_entsize = extract_u64_le(buffer, base + 56)

        section_headers.append({
            "sh_name": f"0x{sh_name:x}",
            "sh_type": f"0x{sh_type:x}",
            "sh_flags": f"0x{sh_flags:x}",
            "sh_addr": f"0x{sh_addr:x}",
            "sh_offset": f"0x{sh_offset:x}",
            "sh_size": f"0x{sh_size:x}",
            "sh_link": f"0x{sh_link:x}",
            "sh_info": f"0x{sh_info:x}",
            "sh_addralign": f"0x{sh_addralign:x}",
            "sh_entsize": f"0x{sh_entsize:x}",
        })

    for idx, sh in enumerate(section_headers, 1):
        elf_data.update({
            f"sh{idx}_sh_name": sh['sh_name'],
            f"sh{idx}_sh_type": sh['sh_type'],
            f"sh{idx}_sh_flags": sh['sh_flags'],
            f"sh{idx}_sh_addr": sh['sh_addr'],
            f"sh{idx}_sh_offset": sh['sh_offset'],
            f"sh{idx}_sh_size": sh['sh_size'],
            f"sh{idx}_sh_link": sh['sh_link'],
            f"sh{idx}_sh_info": sh['sh_info'],
            f"sh{idx}_sh_addralign": sh['sh_addralign'],
            f"sh{idx}_sh_entsize": sh['sh_entsize'],
        })

    return elf_data


def parse_macho(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack("<IIIIII", f.read(24))
        
        return {
            "magic": hex(magic),
            "cputype": hex(cputype),
            "cpusubtype": hex(cpusubtype),
            "filetype": hex(filetype),
            "ncmds": hex(ncmds),
            "sizeofcmds": hex(sizeofcmds),
            "flags": hex(flags),
        }

def generate_toml_report(directory: str) -> None:
    toml_data = {}
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if not os.path.isfile(file_path):
            continue
        
        file_key = os.path.splitext(filename)[0]
        
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
            
            ext = filename.split(".")[-1] if '.' in filename else None
            if magic.startswith(b"MZ"):
                log_message(f"Parsing PE file: {filename}", "info")
                toml_data.setdefault("pe", {})[file_key] = parse_pe(file_path)
                toml_data["pe"][file_key]["file_extension"] = ext
            elif magic.startswith(b"\x7fELF"):
                log_message(f"Parsing ELF file: {filename}", "info")
                toml_data.setdefault("elf", {})[file_key] = parse_elf(file_path)
                toml_data["elf"][file_key]["file_extension"] = ext
            elif magic in [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"]:
                log_message(f"Parsing Mach-O file: {filename}", "info")
                toml_data.setdefault("macho", {})[file_key] = parse_macho(file_path)
                toml_data["macho"][file_key]["file_extension"] = ext
        except Exception as e:
            log_message(f"{traceback.format_exc()}","error")
            log_message(f"Failed to parse {filename}: {e}", "error")
    
    with open(args.output, "w") as file:
        file.write("# M3st3/HexSpell\n")
        file.write("# Auto-generated testing file\n\n")
        toml.dump(toml_data, file)
        log_message(f"TOML file generated: {args.output}", "info")

def main():
    print(header)
    generate_toml_report(args.input)

if __name__ == "__main__":
    main()
