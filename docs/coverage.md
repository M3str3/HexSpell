# Coverage matrix

What HexSpell models today versus known gaps. “Modeled” means the on-disk layout is exposed as
[`Field`] values with real `offset` / `size` (see [guide.md](guide.md)). “Lazy” parsers run on
method call; “Eager” structures are filled during `from_buffer`.

## PE (Windows)

| Area | Status | Access | Notes |
|------|--------|--------|-------|
| DOS / COFF / optional header P0 | Modeled | Eager on `PE::from_buffer` | PE32 + PE32+ |
| Data directories (16 indices) | Modeled | Eager | Gated by `number_of_rva_and_sizes` |
| Section table | Modeled | Eager | `PeSection`, `insert_section` |
| Imports / IAT / hint-name | Modeled | Lazy — `PE::imports` | |
| Exports | Modeled | Lazy — `PE::exports` | Forwarders, ordinals |
| Base relocations | Modeled | Eager — `PE::base_relocations` | Also `reloc::pe_parse_base_relocations` |
| Section COFF relocs | Modeled | Lazy — `PE::section_relocations` | |
| TLS / exceptions / debug / resources | Modeled | Lazy | |
| COFF symbol table + strtab | Modeled | Lazy — `PE::coff_symbols` | Long section names via `strings::pe_section_name` |
| Bound / delay-load imports | Modeled | Lazy | |
| Load config (base fields) | Modeled | Lazy | |
| Rich header / certs / CLR / ARM64x | Modeled | Lazy — `rich_header`, `certificates`, `clr`, `architecture_data` | Read-only certs |
| Line numbers (COFF) | Modeled | Lazy — `section_linenumbers` | |
| Section rename / remove / layout sync | Partial | `layout::rename_section`, `remove_section`, `sync_layout` | Not all edge cases |

## ELF (Linux / BSD)

| Area | Status | Access | Notes |
|------|--------|--------|-------|
| Ehdr / Phdr / Shdr | Modeled | Eager | ELF32 + ELF64, BE + LE |
| Section names / `section_data` | Modeled | Lazy / view | `.shstrtab` resolution |
| `.symtab` / `.dynsym` | Modeled | Lazy | `ELF::symbols`, `ELF::dynamic_symbols` |
| `.dynamic` | Modeled | Lazy — `ELF::dynamic` | `DT_*` tags |
| `.rel` / `.rela` | Modeled | Lazy — `ELF::relocations` | |
| `.hash` / `.gnu.hash` / GNU version | Modeled | Lazy | `sysv_hash`, `gnu_hash`, `version_*` |
| Notes / `.note.gnu.property` | Modeled | Lazy — `note_sections`, `gnu_property_notes` | |
| Unwind / exception blobs | Modeled | Lazy — `eh_frame`, `gcc_except_table` | |
| `insert_section` / `insert_pt_load` | Modeled | Structural helpers | Arbitrary offset, `e_shnum == 0` |
| RELA apply helper | Modeled | `relocation::apply_rela` | |
| PLT/GOT linkage | Modeled | Lazy — `plt_got_sections` | |

## Mach-O (macOS)

| Area | Status | Access | Notes |
|------|--------|--------|-------|
| `mach_header` / load cmd headers | Modeled | Eager | |
| Typed LC (segment, symtab, dyld, dylib, …) | Modeled | Lazy — `typed_commands` | |
| `section` / `section_64` | Modeled | Eager under segments | |
| Symbols + strtab | Modeled | Lazy — `MachO::symbols` | Pool via `strings::macho_symtab_string_pool` |
| Dylib paths | Modeled | Lazy — `linked_dylibs` | |
| Section `relocation_info` | Modeled | Lazy — `relocations` | |
| Export trie / bind opcodes | Modeled | Lazy — `exports`, `bind_opcodes` | |
| Structural LC / section edits | Partial | `insert_load_command_at`, `remove_load_command`, `add_section` | |
| FAT unpack / `from_fat_index` | Modeled | Eager first arch / index select | |
| FAT build / merge / thin slice | Modeled | `FatHeader::build`, `merge`, `slice_ref` | |

## Cross-format (core crate)

| Area | Module | Notes |
|------|--------|-------|
| CString / name helpers | `strings` | PE imports/exports/sections, Mach-O pools |
| VA / file offset | `validation` | Per-format translators |
| Overlap detection | `validation` | Section/segment file ranges |
| Consistency checks | `validation` | Non-fatal `ValidationIssue` list |
| Reloc listing by VA/offset | `reloc` | Thin wrappers per format |
| Layout planner (dry-run) | `write` | `plan_pe_insert_section`, `WriteMode` |

## Iterator / view policy

| API | Strategy |
|-----|----------|
| `PE::section_data`, `ELF::section_data` | Zero-copy `&[u8]` views into `buffer` |
| `PE::imports`, `PE::exports`, ELF/Mach-O symbol tables | Lazy parse; allocates `Vec` of entries |
| `PE::base_relocations` | Eager at parse time (large but usually small) |
| `reloc::pe_parse_base_relocations` | On-demand re-parse of `.reloc` |

[`Field`]: https://docs.rs/hexspell/latest/hexspell/field/struct.Field.html
