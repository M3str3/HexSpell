#[derive(Debug, Clone, Copy)]
pub struct Field<T> {
    pub value: T,
    pub offset: usize,
    pub size: usize,
}

impl<T> Field<T> {
    pub fn new(value: T, offset: usize, size: usize) -> Self {
        Field {
            value,
            offset,
            size,
        }
    }
}

impl Field<u64> {
    /// Updates the buffer at the specified offset with the new value for u64.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u64) {
        self.value = new_value;
        let bytes = new_value.to_le_bytes();
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
    }
}

impl Field<u32> {
    /// Updates the buffer at the specified offset with the new value for u32.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u32) {
        self.value = new_value;
        let bytes = new_value.to_le_bytes();
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
    }
}
impl Field<u16> {
    /// Updates the buffer at the specified offset with the new value for u16.
    pub fn update(&mut self, buffer: &mut [u8], new_value: u16) {
        self.value = new_value;
        let bytes = new_value.to_le_bytes();
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
    }
}

impl Field<String> {
    /// Updates the buffer at the specified offset with the new UTF-8 encoded string.
    pub fn update(&mut self, buffer: &mut [u8], new_value: &String) {
        self.value = new_value.to_string();
        let bytes: &[u8] = self.value.as_bytes();
        if bytes.len() > self.size {
            panic!("New string value exceeds the allocated field size.");
        }

        buffer[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
    }
}
