//! Abstraction for editable fields inside binary buffers.
//!
//! Many binary structures store numeric or string values at fixed offsets.
//! The [`Field`] type pairs such a value with its location and size in the
//! original byte slice, allowing callers to modify the data in place while
//! enforcing bounds and value-size checks.
//!
//! For the `field()` / `field_mut()` convention on ELF and Mach-O layout enums,
//! see `docs/layout.md` in the repository.

use core::fmt;

use crate::errors::FileParseError;

/// Endianness used when reading or writing multi-byte integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOrder {
    /// Little-endian (least significant byte first).
    Little,
    /// Big-endian (most significant byte first).
    Big,
}

impl ByteOrder {
    /// Parses ELF `EI_DATA` (`1` = little-endian, `2` = big-endian).
    pub fn from_elf_data(byte: u8) -> Result<Self, FileParseError> {
        match byte {
            1 => Ok(ByteOrder::Little),
            2 => Ok(ByteOrder::Big),
            _ => Err(FileParseError::InvalidFileFormat),
        }
    }

    /// Alias for [`from_elf_data`](Self::from_elf_data) matching ELF `EI_DATA` naming.
    pub fn from_ei_data(byte: u8) -> Result<Self, FileParseError> {
        Self::from_elf_data(byte)
    }

    /// Derives byte order from the first four bytes of a thin Mach-O header (on disk).
    pub fn from_macho_header_bytes(bytes: [u8; 4]) -> Result<Self, FileParseError> {
        let magic_le = u32::from_le_bytes(bytes);
        match magic_le {
            0xFEEDFACE | 0xFEEDFACF => Ok(ByteOrder::Little),
            0xCEFAEDFE | 0xCFFAEDFE => Ok(ByteOrder::Big),
            _ => Err(FileParseError::InvalidFileFormat),
        }
    }

    pub fn read_u16(self, buffer: &[u8], offset: usize) -> Result<u16, FileParseError> {
        let bytes: [u8; 2] = buffer
            .get(offset..offset + 2)
            .ok_or(FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?;
        Ok(match self {
            ByteOrder::Little => u16::from_le_bytes(bytes),
            ByteOrder::Big => u16::from_be_bytes(bytes),
        })
    }

    pub fn read_u32(self, buffer: &[u8], offset: usize) -> Result<u32, FileParseError> {
        let bytes: [u8; 4] = buffer
            .get(offset..offset + 4)
            .ok_or(FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?;
        Ok(match self {
            ByteOrder::Little => u32::from_le_bytes(bytes),
            ByteOrder::Big => u32::from_be_bytes(bytes),
        })
    }

    pub fn read_u64(self, buffer: &[u8], offset: usize) -> Result<u64, FileParseError> {
        let bytes: [u8; 8] = buffer
            .get(offset..offset + 8)
            .ok_or(FileParseError::BufferOverflow)?
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?;
        Ok(match self {
            ByteOrder::Little => u64::from_le_bytes(bytes),
            ByteOrder::Big => u64::from_be_bytes(bytes),
        })
    }

    pub fn read_u32_slice(self, slice: &[u8]) -> Result<u32, FileParseError> {
        let arr: [u8; 4] = slice
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?;
        Ok(match self {
            ByteOrder::Little => u32::from_le_bytes(arr),
            ByteOrder::Big => u32::from_be_bytes(arr),
        })
    }

    pub fn read_u64_slice(self, slice: &[u8]) -> Result<u64, FileParseError> {
        let arr: [u8; 8] = slice
            .try_into()
            .map_err(|_| FileParseError::BufferOverflow)?;
        Ok(match self {
            ByteOrder::Little => u64::from_le_bytes(arr),
            ByteOrder::Big => u64::from_be_bytes(arr),
        })
    }

    pub fn write_u16(self, buffer: &mut [u8], offset: usize, value: u16) {
        let bytes = match self {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        };
        buffer[offset..offset + 2].copy_from_slice(&bytes);
    }

    pub fn write_u32(self, buffer: &mut [u8], offset: usize, value: u32) {
        let bytes = match self {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        };
        buffer[offset..offset + 4].copy_from_slice(&bytes);
    }

    pub fn write_u64(self, buffer: &mut [u8], offset: usize, value: u64) {
        let bytes = match self {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        };
        buffer[offset..offset + 8].copy_from_slice(&bytes);
    }
}

/// Fixed-size byte array mirroring raw on-disk bytes (section names, `e_ident`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedBytes<N> {
    /// Copies up to `N` bytes from `slice`, zero-padding the remainder.
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut arr = [0u8; N];
        let len = slice.len().min(N);
        arr[..len].copy_from_slice(&slice[..len]);
        Self(arr)
    }

    /// Returns the NUL-terminated UTF-8 prefix (invalid bytes yield an empty string).
    pub fn as_str(&self) -> &str {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(N);
        std::str::from_utf8(&self.0[..end]).unwrap_or("")
    }
}

impl<const N: usize> fmt::Display for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A parsed value together with its absolute offset and on-disk width in the file buffer.
#[derive(Debug, Clone)]
pub struct Field<T> {
    /// Decoded value (may be promoted, e.g. `u32` stored as `u64`).
    pub value: T,
    /// Absolute byte offset from the start of the file buffer.
    pub offset: usize,
    /// Width of this field in the on-disk representation, in bytes.
    pub size: usize,
}

impl<T> Field<T> {
    /// Constructs a field descriptor without reading from a buffer.
    pub fn new(value: T, offset: usize, size: usize) -> Self {
        Field {
            value,
            offset,
            size,
        }
    }
}

/// Mutable accessor returned by `*_mut()` layout methods (fixed-width `u32` / `u16` fields).
pub struct FieldMut<'a, T> {
    field: &'a mut Field<T>,
}

impl<'a> FieldMut<'a, u32> {
    pub fn new(field: &'a mut Field<u32>) -> Self {
        Self { field }
    }

    pub fn value(&self) -> u32 {
        self.field.value
    }

    pub fn offset(&self) -> usize {
        self.field.offset
    }

    pub fn size(&self) -> usize {
        self.field.size
    }

    pub fn update_with(
        &mut self,
        buffer: &mut [u8],
        new_value: u32,
        order: ByteOrder,
    ) -> Result<(), FileParseError> {
        self.field.update_with(buffer, new_value, order)
    }
}

impl<'a> FieldMut<'a, u16> {
    pub fn new(field: &'a mut Field<u16>) -> Self {
        Self { field }
    }

    pub fn value(&self) -> u16 {
        self.field.value
    }

    pub fn offset(&self) -> usize {
        self.field.offset
    }

    pub fn size(&self) -> usize {
        self.field.size
    }

    pub fn update_with(
        &mut self,
        buffer: &mut [u8],
        new_value: u16,
        order: ByteOrder,
    ) -> Result<(), FileParseError> {
        self.field.update_with(buffer, new_value, order)
    }
}

/// Mutable accessor for numeric fields that may be `u32` or `u64` on disk (ELF/Mach-O layouts).
pub enum NumericFieldMut<'a> {
    U32(&'a mut Field<u32>),
    U64(&'a mut Field<u64>),
}

impl<'a> NumericFieldMut<'a> {
    /// Current decoded value (promoted to `u64`).
    pub fn value(&self) -> u64 {
        match self {
            NumericFieldMut::U32(f) => f.value as u64,
            NumericFieldMut::U64(f) => f.value,
        }
    }

    /// Absolute byte offset of this field in the file buffer.
    pub fn offset(&self) -> usize {
        match self {
            NumericFieldMut::U32(f) => f.offset,
            NumericFieldMut::U64(f) => f.offset,
        }
    }

    /// On-disk width of this field in bytes.
    pub fn size(&self) -> usize {
        match self {
            NumericFieldMut::U32(f) => f.size,
            NumericFieldMut::U64(f) => f.size,
        }
    }

    /// Patches the field in `buffer` using the given byte order.
    pub fn update_with(
        &mut self,
        buffer: &mut [u8],
        new_value: u64,
        order: ByteOrder,
    ) -> Result<(), FileParseError> {
        match self {
            NumericFieldMut::U32(f) => f.update_with(buffer, new_value as u32, order),
            NumericFieldMut::U64(f) => f.update_with(buffer, new_value, order),
        }
    }
}

fn write_field_bytes(
    buffer: &mut [u8],
    offset: usize,
    size: usize,
    full_bytes: &[u8],
    order: ByteOrder,
) {
    let slice = &mut buffer[offset..offset + size];
    match order {
        ByteOrder::Little => slice.copy_from_slice(&full_bytes[..size]),
        ByteOrder::Big => {
            let start = full_bytes.len() - size;
            slice.copy_from_slice(&full_bytes[start..]);
        }
    }
}

impl Field<u64> {
    /// Updates the buffer at the specified offset with the new value for u64.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u64) -> Result<(), FileParseError> {
        self.update_with(buffer, new_value, ByteOrder::Little)
    }

    /// Updates the buffer using the specified byte order.
    pub fn update_with(
        &mut self,
        buffer: &mut [u8],
        new_value: u64,
        order: ByteOrder,
    ) -> Result<(), FileParseError> {
        if self.size < std::mem::size_of::<u64>() {
            let bits = (self.size * 8) as u32;
            if (new_value >> bits) != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
        }

        self.value = new_value;
        let full_bytes = match order {
            ByteOrder::Little => new_value.to_le_bytes(),
            ByteOrder::Big => new_value.to_be_bytes(),
        };
        write_field_bytes(buffer, self.offset, self.size, &full_bytes, order);
        Ok(())
    }
}

impl Field<u32> {
    /// Updates the buffer at the specified offset with the new value for u32.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u32) -> Result<(), FileParseError> {
        self.update_with(buffer, new_value, ByteOrder::Little)
    }

    /// Updates the buffer using the specified byte order.
    pub fn update_with(
        &mut self,
        buffer: &mut [u8],
        new_value: u32,
        order: ByteOrder,
    ) -> Result<(), FileParseError> {
        if self.size < std::mem::size_of::<u32>() {
            let bits = (self.size * 8) as u32;
            if (new_value >> bits) != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
        }

        self.value = new_value;
        let full_bytes = match order {
            ByteOrder::Little => new_value.to_le_bytes(),
            ByteOrder::Big => new_value.to_be_bytes(),
        };
        write_field_bytes(buffer, self.offset, self.size, &full_bytes, order);
        Ok(())
    }
}

impl Field<u8> {
    /// Writes a single byte at [`Field::offset`].
    pub fn update(&mut self, buffer: &mut [u8], new_value: u8) -> Result<(), FileParseError> {
        if self.size != 1 {
            return Err(FileParseError::InvalidFileFormat);
        }
        self.value = new_value;
        buffer[self.offset] = new_value;
        Ok(())
    }
}

impl<const N: usize> Field<FixedBytes<N>> {
    /// Replaces the raw bytes, zero-padding to [`Field::size`].
    pub fn update(&mut self, buffer: &mut [u8], new_value: &[u8]) -> Result<(), FileParseError> {
        if new_value.len() > self.size {
            return Err(FileParseError::BufferOverflow);
        }
        let mut arr = [0u8; N];
        arr[..new_value.len()].copy_from_slice(new_value);
        self.value = FixedBytes(arr);
        buffer[self.offset..self.offset + self.size].fill(0);
        buffer[self.offset..self.offset + new_value.len()].copy_from_slice(new_value);
        Ok(())
    }

    /// Convenience wrapper around [`update`](Self::update) for UTF-8 strings.
    pub fn update_str(&mut self, buffer: &mut [u8], new_value: &str) -> Result<(), FileParseError> {
        self.update(buffer, new_value.as_bytes())
    }
}

impl Field<u16> {
    /// Updates the buffer at the specified offset with the new value for u16.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u16) -> Result<(), FileParseError> {
        self.update_with(buffer, new_value, ByteOrder::Little)
    }

    /// Updates the buffer using the specified byte order.
    pub fn update_with(
        &mut self,
        buffer: &mut [u8],
        new_value: u16,
        order: ByteOrder,
    ) -> Result<(), FileParseError> {
        if self.size < std::mem::size_of::<u16>() {
            let bits = (self.size * 8) as u32;
            if (new_value >> bits) != 0 {
                return Err(FileParseError::ValueTooLarge);
            }
        }

        self.value = new_value;
        let full_bytes = match order {
            ByteOrder::Little => new_value.to_le_bytes(),
            ByteOrder::Big => new_value.to_be_bytes(),
        };
        write_field_bytes(buffer, self.offset, self.size, &full_bytes, order);
        Ok(())
    }
}

impl Field<String> {
    /// Updates the buffer at the specified offset with the new UTF-8 encoded string.
    pub fn update(&mut self, buffer: &mut [u8], new_value: &str) -> Result<(), FileParseError> {
        let bytes: &[u8] = new_value.as_bytes();
        if bytes.len() > self.size {
            return Err(FileParseError::BufferOverflow);
        }

        self.value = new_value.to_string();

        buffer[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
        if bytes.len() < self.size {
            buffer[self.offset + bytes.len()..self.offset + self.size].fill(0u8);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_field_mut_u32_writes_four_bytes() {
        let mut buf = vec![0u8; 8];
        let mut field = Field::new(0x1000u32, 0, 4);
        let mut accessor = NumericFieldMut::U32(&mut field);
        accessor
            .update_with(&mut buf, 0xABCD, ByteOrder::Little)
            .unwrap();
        assert_eq!(buf[0..4], 0xABCDu32.to_le_bytes());
        assert_eq!(accessor.value(), 0xABCD);
    }

    #[test]
    fn numeric_field_mut_u64_writes_eight_bytes() {
        let mut buf = vec![0u8; 8];
        let mut field = Field::new(0u64, 0, 8);
        let mut accessor = NumericFieldMut::U64(&mut field);
        accessor
            .update_with(&mut buf, 0x140000000, ByteOrder::Little)
            .unwrap();
        assert_eq!(buf, 0x140000000u64.to_le_bytes());
    }

    #[test]
    fn field_mut_u32_delegates_update() {
        let mut buf = vec![0u8; 4];
        let mut field = Field::new(0u32, 0, 4);
        let mut accessor = FieldMut::<u32>::new(&mut field);
        accessor.update_with(&mut buf, 0x5, ByteOrder::Big).unwrap();
        assert_eq!(buf, 0x5u32.to_be_bytes());
    }

    #[test]
    fn fixed_bytes_update_str_pads_with_zeros() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(b".text\0\0\0");
        let mut field = Field::new(FixedBytes::<8>::from_slice(b".text"), 0, 8);
        field.update_str(&mut buf, ".t").unwrap();
        assert_eq!(&buf[..2], b".t");
        assert_eq!(&buf[2..], [0u8; 6]);
    }

    #[test]
    fn fixed_bytes_update_rejects_overflow() {
        let mut buf = [0u8; 8];
        let mut field = Field::new(FixedBytes::<8>::from_slice(b".text"), 0, 8);
        let err = field.update_str(&mut buf, "longname!!").unwrap_err();
        assert!(matches!(err, FileParseError::BufferOverflow));
    }

    #[test]
    fn from_ei_data_matches_from_elf_data() {
        assert_eq!(
            ByteOrder::from_ei_data(1).unwrap(),
            ByteOrder::from_elf_data(1).unwrap()
        );
    }

    #[test]
    fn from_macho_header_bytes_little_and_big() {
        assert_eq!(
            ByteOrder::from_macho_header_bytes([0xCE, 0xFA, 0xED, 0xFE]).unwrap(),
            ByteOrder::Little
        );
        assert_eq!(
            ByteOrder::from_macho_header_bytes([0xFE, 0xED, 0xFA, 0xCE]).unwrap(),
            ByteOrder::Big
        );
    }
}
