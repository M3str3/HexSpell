# AGENTS

Operational guide for agents working on HexSpell.

HexSpell is a **dependency-free** Rust library for parsing and patching **PE**, **ELF**, and **Mach-O**
executables. The public API mirrors the on-disk layout: header fields are `Field` values with real
`offset` and `size` in the file buffer.

## Core rules

1. **No runtime dependencies** — only `dev-dependencies` for tests (currently `toml`).
2. **Tests required** — every functional change updates tests; bugfixes need a test that fails without the fix.
3. **Small scope** — no unrequested features or drive-by refactors.
4. **Docs when behavior changes** — see [Documentation and changelog](#documentation-and-changelog).
5. **Finish with** `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.

Design constraints (do not break casually):

- **1:1 with the file format** — fields live where the spec places them; expose `Field` with correct `offset` / `size`.
- **Explicit buffer** — patch via `Field::update`, `update_with` (ELF/Mach-O endianness), or layout helpers on `pe.buffer` / `elf.buffer` / `macho.buffer`.
- **Lazy vs eager** — headers/sections eager in `from_buffer`; directory tables and heavy parsers on method call (`PE::imports`, `ELF::dynamic`, …). See `docs/coverage.md`.
- **Reuse existing types** — `Field`, `FixedBytes`, `ByteOrder`, `FileParseError` before new abstractions.
- **Breaking changes** — semver bump + `CHANGELOG.md` entry with **Breaking**.

## Task recipes

| Task | Do |
|------|-----|
| **New lazy parser** | `src/{pe,elf,macho}/foo.rs` → method on format type → test in `tests/{pe,elf,macho}.rs` → row in `docs/coverage.md` (+ `docs/guide.md` if public API) |
| **Bugfix** | Reproduce in test → minimal fix → `cargo test` |
| **Structural edit** (section insert, layout sync) | Use existing helpers (`insert_section`, `sync_layout`, …); add round-trip test |
| **Docs only** | Edit `docs/` / `README.md`; changelog only if user-visible |

Example — add `PE::foo()` for a data directory:

1. Parser in `src/pe/foo.rs`, wire in `src/pe/mod.rs`.
2. `impl PE { pub fn foo(&self) -> Result<...> }` reading from `self.buffer` at directory RVA.
3. Test in `tests/pe.rs` against `tests/samples/sample1.exe`.
4. Row in `docs/coverage.md`; changelog if user-facing.

## Common pitfalls

- **`tests/*` is not part of the published crate** (`exclude` in `Cargo.toml`) — integration tests live there; library code stays in `src/`.
- **`generator.py` is PE32-centric** — it fills `tests/tests.toml` for most fixtures; `sample64.exe` is validated only by `test_pe64_parse` in `tests/pe.rs`, not `tests.toml`.
- **PE32 vs PE32+** — optional header layout differs (`base_of_data`, `image_base` width, data directory count). Do not assume PE32 field offsets on PE64.
- **PE RVA vs file offset** — `rva_to_offset` maps only RVAs covered by `SizeOfRawData` (file-backed ranges), not every RVA.
- **ELF / Mach-O endianness** — read `ei_data` / header magic; use `ByteOrder` and `update_with`, not raw little-endian writes.
- **Section names** — PE uses `Field<FixedBytes<8>>` (`name_str()` for display); long COFF names go through `strings::pe_section_name`.
- **New binaries** — every file in `tests/samples/` needs provenance in `tests/readme.md` and usually a rebuild recipe in `tests/source/`.
- **Warnings are errors in CI** — `RUSTFLAGS="-D warnings"` and `cargo clippy --all-targets -- -D warnings` in `.github/workflows/rust.yml`.

## Repo map

- `src/field.rs` — `Field`, `FixedBytes`, `ByteOrder`.
- `src/pe/`, `src/elf/`, `src/macho/` — format parsers and layout.
- `src/errors.rs`, `src/validation.rs`, `src/strings.rs`, `src/reloc.rs`, `src/write.rs` — shared helpers.
- `tests/pe.rs`, `tests/elf.rs`, `tests/macho.rs` — format integration tests.
- `tests/general.rs`, `tests/cross_format.rs` — shared and cross-format tests.
- `tests/samples/`, `tests/source/`, `tests/scripts/generator.py`, `tests/tests.toml` — fixtures and expected values.
- `docs/guide.md`, `docs/layout.md`, `docs/coverage.md` — human docs; keep aligned with code.

## Testing

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test                    # full suite
cargo test --test pe          # PE only
cargo test test_pe64_parse    # PE32+ fixture
```

After changing PE/ELF/Mach-O expectations for `tests.toml` fixtures: `python tests/scripts/generator.py`, then review the diff.

## Documentation and changelog

Update when visible library behavior or public API changes:

| File | When |
|------|------|
| `docs/guide.md` | Usage / examples |
| `docs/layout.md` | Field accessor tables |
| `docs/coverage.md` | New or changed modeled areas |
| `README.md` | User-facing surface |
| `CHANGELOG.md` | User-relevant changes only (not test-only or internal refactors) |

Changelog format: version → module (**General** > **PE** > **ELF** > **Mach-O**) → type (*Added* > *Changed* > *Fixed* > *Documentation* > *Chore*). Mark **Breaking** explicitly.
