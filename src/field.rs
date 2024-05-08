#[derive(Debug, Clone, Copy)]
pub struct Field<T> {
    pub value: T,
    pub offset: usize,
    pub size: usize,
}

impl Field<u32> {
    /// Updates the buffer at the specified offset with the new value for u32.
    pub fn update(&mut self, buffer: &mut Vec<u8>, new_value: u32) {
        self.value = new_value;
        let mut bytes: [u8; 4] = [0u8; 4]; 
        bytes[0] = (new_value & 0xff) as u8;
        bytes[1] = ((new_value >> 8) & 0xff) as u8;
        bytes[2] = ((new_value >> 16) & 0xff) as u8;
        bytes[3] = ((new_value >> 24) & 0xff) as u8;
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
    }
}

impl Field<u16> {
    /// Updates the buffer at the specified offset with the new value for u16.
    pub fn update(&mut self, buffer: &mut Vec<u8>, new_value: u16) {
        self.value = new_value;
        let mut bytes: [u8; 2] = [0u8; 2];  
        bytes[0] = (new_value & 0xff) as u8;
        bytes[1] = ((new_value >> 8) & 0xff) as u8;
        buffer[self.offset..self.offset + self.size].copy_from_slice(&bytes[..self.size]);
    }
}

impl Field<String> {
    /// Updates the buffer at the specified offset with the new UTF-8 encoded string.
    pub fn update(&mut self, buffer: &mut Vec<u8>, new_value: &String) {
        self.value = new_value.to_string();
        let bytes: &[u8] = self.value.as_bytes(); 
        if bytes.len() > self.size {
            panic!("New string value exceeds the allocated field size.");
        }

        buffer[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);

    }
}