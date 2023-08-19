pub(super) fn hash_bytes(name: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hash = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut hash);
    hash.finish()
}
