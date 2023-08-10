/// Trait to serialize/deserialize parts of DNS packets
pub trait ByteConvertible {
    fn byte_size(&self) -> usize;

    fn to_bytes(&self) -> Vec<u8>;
}

pub trait CompressedByteConvertible {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        offset: usize,
    ) -> Vec<u8>;
}
