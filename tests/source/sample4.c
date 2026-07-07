// PE64 (x86_64, PE32+) test binary for HexSpell regression tests.
//
// Purpose: verify parsing of 64-bit PE optional header fields (ImageBase u64,
// absence of BaseOfData, architecture x64). Used by test_pe64_parse in tests/pe.rs.
//
// Build (Linux/WSL with mingw-w64 installed):
//   x86_64-w64-mingw32-gcc tests/source/sample4.c -o tests/samples/sample64.exe
//
// Build (Windows, MSVC or mingw on PATH):
//   x86_64-w64-mingw32-gcc tests\source\sample4.c -o tests\samples\sample64.exe
//
// Requirements: mingw-w64 cross-compiler (e.g. apt install gcc-mingw-w64-x86-64)

int main(void) {
    return 0;
}
