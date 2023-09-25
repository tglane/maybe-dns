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
