/// Traits

pub trait ByteConvertible {
    fn byte_size(&self) -> usize;

    fn to_bytes(&self) -> Vec<u8>;

    fn to_bytes_compressed(&self, names: &mut std::collections::HashMap::<u64, usize>, offset: usize) -> Vec<u8>;
}


/// Free functions

pub fn hash_bytes(name: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hash = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut hash);
    hash.finish()
}
