//! ELF symbol hash tables (`.hash` and `.gnu.hash`).

use crate::errors::FileParseError;
use crate::field::{ByteOrder, Field};

/// System V `.hash` table.
pub struct SysvHashTable {
    /// `nbucket` field.
    pub nbucket: Field<u32>,
    /// `nchain` field.
    pub nchain: Field<u32>,
    /// Bucket array entries.
    pub buckets: Vec<Field<u32>>,
    /// Chain array entries.
    pub chains: Vec<Field<u32>>,
}

impl SysvHashTable {
    /// Parses a System V hash table at `offset`.
    pub fn parse(buffer: &[u8], offset: usize, order: ByteOrder) -> Result<Self, FileParseError> {
        let nbucket = Field::new(order.read_u32(buffer, offset)?, offset, 4);
        let nchain = Field::new(order.read_u32(buffer, offset + 4)?, offset + 4, 4);
        let mut cursor = offset + 8;
        let mut buckets = Vec::with_capacity(nbucket.value as usize);
        for _ in 0..nbucket.value {
            buckets.push(Field::new(order.read_u32(buffer, cursor)?, cursor, 4));
            cursor += 4;
        }
        let mut chains = Vec::with_capacity(nchain.value as usize);
        for _ in 0..nchain.value {
            chains.push(Field::new(order.read_u32(buffer, cursor)?, cursor, 4));
            cursor += 4;
        }
        Ok(Self {
            nbucket,
            nchain,
            buckets,
            chains,
        })
    }
}

/// GNU `.gnu.hash` table.
pub struct GnuHashTable {
    /// `nbuckets` field.
    pub nbuckets: Field<u32>,
    /// `symoffset` field.
    pub symoffset: Field<u32>,
    /// `bloom_size` field.
    pub bloom_size: Field<u32>,
    /// `bloom_shift` field.
    pub bloom_shift: Field<u32>,
    /// Bloom filter words (`u32` on ELF32, `u64` on ELF64 promoted to `u64`).
    pub bloom: Vec<Field<u64>>,
    /// Bucket array entries.
    pub buckets: Vec<Field<u32>>,
    /// Chain array entries.
    pub chains: Vec<Field<u32>>,
}

impl GnuHashTable {
    /// Parses a GNU hash table at `offset`; `size` bounds the variable chain array.
    pub fn parse(
        buffer: &[u8],
        offset: usize,
        size: usize,
        word_size: usize,
        order: ByteOrder,
    ) -> Result<Self, FileParseError> {
        if word_size != 4 && word_size != 8 {
            return Err(FileParseError::InvalidFileFormat);
        }
        let end = offset
            .checked_add(size)
            .ok_or(FileParseError::BufferOverflow)?;
        let nbuckets = Field::new(order.read_u32(buffer, offset)?, offset, 4);
        let symoffset = Field::new(order.read_u32(buffer, offset + 4)?, offset + 4, 4);
        let bloom_size = Field::new(order.read_u32(buffer, offset + 8)?, offset + 8, 4);
        let bloom_shift = Field::new(order.read_u32(buffer, offset + 12)?, offset + 12, 4);
        let mut cursor = offset + 16;

        let mut bloom = Vec::with_capacity(bloom_size.value as usize);
        for _ in 0..bloom_size.value {
            let value = if word_size == 4 {
                order.read_u32(buffer, cursor)? as u64
            } else {
                order.read_u64(buffer, cursor)?
            };
            bloom.push(Field::new(value, cursor, word_size));
            cursor += word_size;
        }

        let mut buckets = Vec::with_capacity(nbuckets.value as usize);
        for _ in 0..nbuckets.value {
            buckets.push(Field::new(order.read_u32(buffer, cursor)?, cursor, 4));
            cursor += 4;
        }

        let mut chains = Vec::new();
        while cursor + 4 <= end {
            chains.push(Field::new(order.read_u32(buffer, cursor)?, cursor, 4));
            cursor += 4;
        }

        Ok(Self {
            nbuckets,
            symoffset,
            bloom_size,
            bloom_shift,
            bloom,
            buckets,
            chains,
        })
    }
}
