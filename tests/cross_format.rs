//! Cross-format helpers, round-trip regression, FAT selection, and endianness tests.

use hexspell::elf;
use hexspell::field::ByteOrder;
use hexspell::macho;
use hexspell::pe;
use hexspell::reloc;
use hexspell::strings;
use hexspell::validation;
use hexspell::write::{plan_pe_insert_section, WriteMode};

// --- String helpers ---

#[test]
fn pe_import_and_export_strings_on_fixtures() {
    let pe32 = pe::PE::from_file("tests/samples/sample1.exe").expect("sample1");
    let imports = strings::pe_import_strings(&pe32).expect("imports");
    assert!(!imports.is_empty());
    assert!(imports.iter().any(|(dll, _)| dll.contains("KERNEL32")));

    let pe_dll = pe::PE::from_file("tests/samples/sample2.dll").expect("sample2");
    let exports = strings::pe_export_names(&pe_dll).expect("exports");
    assert!(exports.iter().any(|n| n == "Add"));
}

#[test]
fn pe_section_names_short_and_via_helper() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("sample1");
    for (i, section) in pe.sections.iter().enumerate() {
        let resolved = strings::pe_section_name(&pe, i).expect("section name");
        assert_eq!(resolved, section.name_str());
    }
}

#[test]
fn pe_long_section_name_from_coff_string_table() {
    let mut buffer = vec![0u8; 0x120];
    let strtab = 0x102;
    buffer[strtab..strtab + 4].copy_from_slice(&20u32.to_le_bytes());
    buffer[strtab + 4..strtab + 18].copy_from_slice(b".verylongname\0");

    // First string in the COFF table starts immediately after the 4-byte size prefix.
    let name_off = strtab + 4;
    assert_eq!(
        strings::read_c_string(&buffer, name_off).unwrap(),
        ".verylongname"
    );
}

#[test]
fn macho_cstring_pool_and_dylibs() {
    let macho = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls").expect("macho");
    let pool = strings::macho_symtab_string_pool(&macho)
        .expect("pool")
        .expect("symtab");
    assert!(pool.size > 0);

    let symtab = macho.symbols().expect("symbols").expect("symtab");
    let first_named = symtab
        .symbols
        .iter()
        .find(|s| !s.name.is_empty())
        .expect("named symbol");
    let via_pool = pool
        .resolve(&macho.buffer, first_named.n_strx.value as usize)
        .expect("resolve");
    assert_eq!(via_pool, first_named.name);

    let dylibs = strings::macho_dylib_paths(&macho).expect("dylibs");
    assert!(!dylibs.is_empty());
}

// --- Validation ---

#[test]
fn validation_pe_rva_va_and_consistency() {
    let pe = pe::PE::from_file("tests/samples/sample2.dll").expect("sample2");
    let export_rva = pe.optional_header.data_directories[pe::header::EXPORT]
        .virtual_address
        .value;
    let off = validation::pe_rva_to_file_offset(&pe, export_rva).expect("rva");
    assert_eq!(off, 0x1e00);

    let base = match pe.optional_header.image_base.value {
        pe::header::ImageBase::Base32(v) => v as u64,
        pe::header::ImageBase::Base64(v) => v,
    };
    assert_eq!(
        validation::pe_va_to_file_offset(&pe, base + export_rva as u64).expect("va"),
        off
    );

    let issues = validation::pe_consistency(&pe);
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn validation_elf_va_translation() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("linux");
    let text_idx = elf.section_index_by_name(".text").expect(".text");
    let sh = &elf.section_headers[text_idx];
    let va = sh.sh_addr();
    let off = validation::elf_va_to_file_offset(&elf, va).expect("va->off");
    assert_eq!(off, sh.sh_offset() as usize);
}

#[test]
fn validation_overlap_detection_synthetic() {
    let ranges = vec![
        validation::FileRange {
            label: "a".into(),
            start: 0,
            end: 16,
        },
        validation::FileRange {
            label: "b".into(),
            start: 8,
            end: 24,
        },
    ];
    let overlaps = validation::find_overlaps(&ranges);
    assert_eq!(overlaps.len(), 1);
}

// --- Relocations ---

#[test]
fn reloc_pe_base_relocs_sample2() {
    let pe = pe::PE::from_file("tests/samples/sample2.dll").expect("sample2");
    let hits = reloc::pe_base_relocs(&pe).expect("base relocs");
    assert!(!hits.is_empty());
    assert!(hits.iter().all(|hit| hit.file_offset > 0));
}

#[test]
fn reloc_pe_base_relocs_surfaces_mapping_error() {
    use hexspell::field::Field;
    use pe::relocation::{BaseRelocationBlock, BaseRelocationEntry};

    let mut pe = pe::PE::from_file("tests/samples/sample2.dll").expect("sample2");
    pe.base_relocations.push(BaseRelocationBlock {
        page_rva: Field::new(0xFFFF_0000, 0, 4),
        block_size: Field::new(12, 0, 4),
        entries: vec![BaseRelocationEntry {
            raw: Field::new(0x0000, 0, 2),
        }],
    });

    assert!(reloc::pe_base_relocs(&pe).is_err());
}

#[test]
fn reloc_pe_base_relocs_at_rva_sample2() {
    let pe = pe::PE::from_file("tests/samples/sample2.dll").expect("sample2");
    assert!(!pe.base_relocations.is_empty());
    let rva = pe.base_relocations[0].entries[0].rva(pe.base_relocations[0].page_rva.value);
    let hits = reloc::pe_base_relocs_at_rva(&pe, rva).expect("hits");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rva, rva);
}

#[test]
fn reloc_elf_at_va_linux() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("linux");
    let plt_idx = elf.section_index_by_name(".rela.plt").expect(".rela.plt");
    let relocs = elf.relocations().expect("relocs");
    let (_, entries) = relocs.iter().find(|(i, _)| *i == plt_idx).expect("plt");
    let va = entries[0].r_offset();
    let hits = reloc::elf_relocs_at_va(&elf, va).expect("hits");
    assert!(!hits.is_empty());
}

#[test]
fn reloc_pe_lazy_parse_matches_eager() {
    let pe = pe::PE::from_file("tests/samples/sample64.exe").expect("pe64");
    let lazy = reloc::pe_parse_base_relocations(&pe).expect("lazy");
    assert_eq!(lazy.len(), pe.base_relocations.len());
}

// --- Write planner ---

#[test]
fn write_plan_pe_insert_section() {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("sample1");
    let plan = plan_pe_insert_section(
        &pe,
        &pe::section::NewSection {
            name: ".plan".into(),
            data: vec![0u8; 64],
            characteristics: pe::section::READ,
        },
    )
    .expect("plan");
    assert!(plan.new_buffer_len > pe.buffer.len());
    assert!(WriteMode::DryRun.is_dry_run());
}

// --- Round-trip: parse → patch → write → re-parse ---

#[test]
fn round_trip_pe_entry_point() {
    let mut pe = pe::PE::from_file("tests/samples/sample1.exe").expect("parse");
    let old = pe.optional_header.entry_point.value;
    let new = old.wrapping_add(0x10);
    pe.optional_header
        .entry_point
        .update(&mut pe.buffer, new)
        .expect("patch");

    let tmp = std::env::temp_dir().join("hexspell_rt_pe.exe");
    pe.write_file(tmp.to_str().unwrap()).expect("write");

    let reparsed = pe::PE::from_file(tmp.to_str().unwrap()).expect("reparse");
    assert_eq!(reparsed.optional_header.entry_point.value, new);
    std::fs::remove_file(tmp).ok();
}

#[test]
fn round_trip_elf_entry_point() {
    let mut elf = elf::ELF::from_file("tests/samples/linux").expect("parse");
    let order = elf.byte_order().expect("order");
    let new = elf.header.entry.value.wrapping_add(0x100);
    elf.header
        .entry
        .update_with(&mut elf.buffer, new, order)
        .expect("patch");

    let tmp = std::env::temp_dir().join("hexspell_rt_elf");
    elf.write_file(tmp.to_str().unwrap()).expect("write");

    let reparsed = elf::ELF::from_file(tmp.to_str().unwrap()).expect("reparse");
    assert_eq!(reparsed.header.entry.value, new);
    std::fs::remove_file(tmp).ok();
}

#[test]
fn round_trip_macho_ncmds() {
    let mut macho = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls").expect("parse");
    let order = macho.byte_order();
    let old = macho.header.ncmds.value;
    macho
        .header
        .ncmds
        .update_with(&mut macho.buffer, old, order)
        .expect("patch");

    let tmp = std::env::temp_dir().join("hexspell_rt_macho");
    macho.write_file(tmp.to_str().unwrap()).expect("write");

    let reparsed = macho::MachO::from_file(tmp.to_str().unwrap()).expect("reparse");
    assert_eq!(reparsed.header.ncmds.value, old);
    std::fs::remove_file(tmp).ok();
}

// --- FAT multi-arch ---

fn build_fat_two_arch() -> Vec<u8> {
    let thin = |magic: u32| -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(&magic.to_le_bytes());
        b[16..20].copy_from_slice(&0u32.to_le_bytes());
        b
    };
    let arch1 = thin(0xFEED_FACF);
    let arch2 = thin(0xFEED_FACE);
    let fat_size = 8 + 40; // header + one fat_arch (32-bit)
    let off1 = fat_size;
    let off2 = off1 + arch1.len();
    let mut fat = vec![0u8; off2 + arch2.len()];
    fat[0..4].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    fat[4..8].copy_from_slice(&2u32.to_be_bytes());
    // arch 0 — 64-bit slice
    fat[8..12].copy_from_slice(&0x0100_000Cu32.to_be_bytes()); // CPU_TYPE_ARM64
    fat[12..16].copy_from_slice(&0u32.to_be_bytes());
    fat[16..20].copy_from_slice(&(off1 as u32).to_be_bytes());
    fat[20..24].copy_from_slice(&(arch1.len() as u32).to_be_bytes());
    fat[24..28].copy_from_slice(&0u32.to_be_bytes());
    // arch 1 — 32-bit slice
    fat[28..32].copy_from_slice(&0x0000_0007u32.to_be_bytes()); // CPU_TYPE_X86
    fat[32..36].copy_from_slice(&0u32.to_be_bytes());
    fat[36..40].copy_from_slice(&(off2 as u32).to_be_bytes());
    fat[40..44].copy_from_slice(&(arch2.len() as u32).to_be_bytes());
    fat[44..48].copy_from_slice(&0u32.to_be_bytes());
    fat[off1..off1 + arch1.len()].copy_from_slice(&arch1);
    fat[off2..off2 + arch2.len()].copy_from_slice(&arch2);
    fat
}

#[test]
fn fat_two_architectures_selection() {
    let buffer = build_fat_two_arch();
    let arches = macho::fat::FatHeader::parse(&buffer)
        .expect("parse")
        .expect("fat");
    assert_eq!(arches.arches.len(), 2);

    let m0 = macho::MachO::from_fat_index_buffer(buffer.clone(), 0).expect("arch0");
    assert!(m0.header.reserved.is_some());

    let m1 = macho::MachO::from_fat_index_buffer(buffer, 1).expect("arch1");
    assert!(m1.header.reserved.is_none());
}

// --- Big-endian regression expansion ---

#[test]
fn big_endian_elf_shdr_field_round_trip() {
    let mut buffer = vec![0u8; 256];
    buffer[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buffer[4] = 2;
    buffer[5] = 2; // big-endian
    buffer[6] = 1;
    buffer[32..40].copy_from_slice(&64u64.to_be_bytes());
    buffer[40..48].copy_from_slice(&120u64.to_be_bytes());
    buffer[58..60].copy_from_slice(&1u16.to_be_bytes());
    buffer[60..62].copy_from_slice(&64u16.to_be_bytes());

    let sh = 120usize;
    buffer[sh..sh + 4].copy_from_slice(&1u32.to_be_bytes()); // .text name off
    buffer[sh + 4..sh + 8].copy_from_slice(&1u32.to_be_bytes()); // SHT_PROGBITS
    buffer[sh + 16..sh + 24].copy_from_slice(&0x1000u64.to_be_bytes());
    buffer[sh + 24..sh + 32].copy_from_slice(&0x200u64.to_be_bytes());
    buffer[sh + 32..sh + 40].copy_from_slice(&0x80u64.to_be_bytes());

    let mut elf = elf::ELF::from_buffer(buffer).expect("be elf");
    assert_eq!(elf.byte_order().unwrap(), ByteOrder::Big);
    let new_addr = 0x2000u64;
    elf.section_headers[0]
        .sh_addr_mut()
        .update_with(&mut elf.buffer, new_addr, ByteOrder::Big)
        .expect("patch");

    let reparsed = elf::ELF::from_buffer(elf.buffer).expect("reparse");
    assert_eq!(reparsed.section_headers[0].sh_addr(), new_addr);
}

#[test]
fn big_endian_macho_segment_vmaddr_round_trip() {
    let mut buffer = vec![0u8; 128];
    buffer[0..4].copy_from_slice(&[0xFE, 0xED, 0xFA, 0xCE]); // 32-bit BE magic
    buffer[16..20].copy_from_slice(&1u32.to_be_bytes());
    buffer[20..24].copy_from_slice(&56u32.to_be_bytes());
    let seg = 28usize;
    buffer[seg..seg + 4].copy_from_slice(&1u32.to_be_bytes()); // LC_SEGMENT
    buffer[seg + 4..seg + 8].copy_from_slice(&56u32.to_be_bytes());
    buffer[seg + 8..seg + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    buffer[seg + 24..seg + 28].copy_from_slice(&0x1000u32.to_be_bytes());

    let mut macho = macho::MachO::from_buffer(buffer).expect("be macho");
    assert_eq!(macho.byte_order(), ByteOrder::Big);
    macho.segments[0]
        .vmaddr_mut()
        .update_with(&mut macho.buffer, 0x2000, ByteOrder::Big)
        .expect("patch");

    let reparsed = macho::MachO::from_buffer(macho.buffer).expect("reparse");
    assert_eq!(reparsed.segments[0].vmaddr(), 0x2000);
}

/// PE sample1: imports + TLS; sample2: exports + relocs; synthetic resource test lives in pe.rs.
#[test]
fn fixture_pe_combined_features() {
    let pe32 = pe::PE::from_file("tests/samples/sample1.exe").expect("sample1");
    assert!(!pe32.imports().unwrap().dlls.is_empty());
    assert!(pe32.tls().unwrap().is_some());

    let dll = pe::PE::from_file("tests/samples/sample2.dll").expect("sample2");
    assert!(dll.exports().unwrap().is_some());
    assert!(!dll.base_relocations.is_empty());
}

/// ELF ET_DYN with dynamic linking tables (tests/samples/linux).
#[test]
fn fixture_elf_et_dyn() {
    let elf = elf::ELF::from_file("tests/samples/linux").expect("linux");
    assert_eq!(
        elf.header.elf_type.value,
        elf::header::ElfType::SharedObject
    ); // ET_DYN
    assert!(elf.dynamic().unwrap().is_some());
    assert!(elf.dynamic_symbols().unwrap().is_some());
    assert!(elf
        .relocations()
        .unwrap()
        .iter()
        .any(|(_, e)| !e.is_empty()));
}

/// Mach-O with dyld info, dylinker, and multiple dylibs.
#[test]
fn fixture_macho_dyld() {
    let macho = macho::MachO::from_file("tests/samples/machO-OSX-x86-ls").expect("macho");
    let typed = macho.typed_commands().expect("typed");
    assert!(typed
        .iter()
        .any(|c| matches!(c, macho::load_command::TypedCommand::DyldInfo(_))));
    assert!(typed
        .iter()
        .any(|c| matches!(c, macho::load_command::TypedCommand::Dylinker(_))));
    let dylibs = macho.linked_dylibs().expect("dylibs");
    assert!(dylibs.len() >= 2);
}
