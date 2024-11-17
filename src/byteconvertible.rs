use std::collections::HashMap;

/// Trait to serialize/deserialize parts of DNS packets
pub trait ByteConvertible {
    /// Calculate the length of the binary representation of implementer.
    /// This is equal to the length of the buffer returned by `to_bytes`.
    fn byte_size(&self) -> usize;

    /// Create binary representation of the implementer
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait CompressedByteConvertible {
    /// Calculate the length of the binary representation of implementer with DNS compression.
    /// This is equal to the length of the buffer returned by `to_bytes_compressed`.
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        self.to_bytes_compressed(names, offset).len()
    }

    /// Create binary representation of the implementer that utilizes DNS compression
    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8>;
}
