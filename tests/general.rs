use hexspell::errors::FileParseError;
use hexspell::field::Field;
use hexspell::pe;

// Support function
fn load_section_name_field() -> (Vec<u8>, Field<String>) {
    let pe = pe::PE::from_file("tests/samples/sample1.exe").expect("Cannot open the PE");
    let buffer_clone = pe.buffer.clone();
    let field = pe.sections[0].name.clone();
    (buffer_clone, field)
}

#[test]
fn test_field_u32_value_bounds() {
    let mut buffer = [0u8; 3];
    let mut field = Field::new(0u32, 0, 3);
    field.update(&mut buffer, 0x00ABCDEFu32).unwrap();
    assert_eq!(
        &buffer,
        &0x00ABCDEFu32.to_le_bytes()[..3],
        "u32 bytes were not written correctly",
    );

    let err = field.update(&mut buffer, 0x01000000u32).unwrap_err();
    assert!(matches!(err, FileParseError::ValueTooLarge));
}

#[test]
fn test_field_u16_value_bounds() {
    let mut buffer = [0u8; 1];
    let mut field = Field::new(0u16, 0, 1);
    field.update(&mut buffer, 0x7Fu16).unwrap();
    assert_eq!(buffer[0], 0x7Fu8, "u16 byte was not written correctly");

    let err = field.update(&mut buffer, 0x1FFu16).unwrap_err();
    assert!(matches!(err, FileParseError::ValueTooLarge));
}

#[test]
fn test_field_u64_value_bounds() {
    let mut buffer = [0u8; 7];
    let mut field = Field::new(0u64, 0, 7);
    field.update(&mut buffer, 0x00DEADBEEFCAFEu64).unwrap();
    assert_eq!(
        &buffer,
        &0x00DEADBEEFCAFEu64.to_le_bytes()[..7],
        "u64 bytes were not written correctly",
    );

    let err = field
        .update(&mut buffer, 0x0100000000000000u64)
        .unwrap_err();
    assert!(matches!(err, FileParseError::ValueTooLarge));
}

#[test]
fn test_padding_shorter() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let new_name = ".t".to_string();
    let offset = name_field.offset;
    let size = name_field.size;

    name_field.update(&mut buffer, &new_name).unwrap();

    assert_eq!(
        &buffer[offset..offset + new_name.len()],
        new_name.as_bytes()
    );

    assert!(
        buffer[offset + new_name.len()..offset + size]
            .iter()
            .all(|&b| b == 0),
        "Remaining bytes were not zero-padded"
    );
}

#[test]
fn test_exact_fit() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let size = name_field.size;
    let exact = "X".repeat(size);
    let offset = name_field.offset;

    name_field.update(&mut buffer, &exact).unwrap();

    assert_eq!(
        &buffer[offset..offset + size],
        exact.as_bytes(),
        "Exact-fit write failed"
    );
}

#[test]
fn test_overflow_error() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let size = name_field.size;
    let overflow = "A".repeat(size + 1);

    let err = name_field
        .update(&mut buffer, &overflow)
        .expect_err("Expected a BufferOverflow error");

    assert!(
        matches!(err, FileParseError::BufferOverflow),
        "Expected BufferOverflow, got {:?}",
        err
    );
}

#[test]
fn test_utf8_multibyte() {
    let (mut buffer, mut name_field) = load_section_name_field();
    let new_name = "ñáç".to_string();
    let bytes = new_name.as_bytes();
    let size = name_field.size;
    let offset = name_field.offset;

    assert!(
        bytes.len() <= size,
        "UTF-8 byte length ({}) exceeds field size ({})",
        bytes.len(),
        size
    );

    name_field.update(&mut buffer, &new_name).unwrap();

    assert_eq!(
        &buffer[offset..offset + bytes.len()],
        bytes,
        "UTF-8 bytes were not written correctly"
    );

    assert!(
        buffer[offset + bytes.len()..offset + size]
            .iter()
            .all(|&b| b == 0),
        "Remaining bytes were not zero-padded after UTF-8 write"
    );
}
