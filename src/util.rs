/// Traits

pub trait ByteConvertible {
    fn byte_size(&self) -> usize;

    fn to_bytes(&self) -> Vec<u8>;
}
