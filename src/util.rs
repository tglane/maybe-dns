/// Generates a hash from a fully-qualified domain name (FQDN).
///
/// Use case:
/// This is used internally to for DNS compression agorithm. When serializing a DNS packet, a
/// hash of any occuring FQDN is added in order of occurence into a hashmap. When another FQDN
/// gets serialized, we can check for previous occurences by simple table lookup to create a
/// pointer.
pub(super) fn hash_fqdn(fqdn: &[Vec<u8>]) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hash = std::collections::hash_map::DefaultHasher::new();
    fqdn.hash(&mut hash);
    hash.finish()
}

#[cfg(test)]
mod tests {
    use super::hash_fqdn;

    #[test]
    fn transitive_hashes() {
        let a = vec![vec![55, 55, 55], vec![22, 34, 54, 98, 22], vec![1, 2, 3]];
        let b = vec![vec![55, 55, 55], vec![22, 34, 54, 98, 22], vec![1, 2, 3]];

        assert_eq!(hash_fqdn(&a), hash_fqdn(&b));
        assert_eq!(hash_fqdn(&b), hash_fqdn(&a));
    }
}
