use std::collections::HashMap;
use std::convert::{From, TryFrom};
use std::fmt::Display;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::util::hash_fqdn;
use crate::COMPRESSION_MASK_U16;

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FQDN {
    // TODO: Store data in a flattend representation (Vec<u8> instead of Vec<Vec<u8>>)
    data: Vec<Vec<u8>>,
}

impl FQDN {
    pub fn new(name: &str) -> Self {
        Self {
            data: name
                .split('.')
                .filter(|s| !s.is_empty())
                .map(|s| s.as_bytes().to_vec())
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.byte_size() == 0
    }

    pub fn len(&self) -> usize {
        self.byte_size()
    }

    pub fn label_count(&self) -> u8 {
        self.data.len() as u8
    }

    pub fn iter(&self) -> std::slice::Iter<Vec<u8>> {
        self.data.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<Vec<u8>> {
        self.data.iter_mut()
    }

    pub fn is_link_local(&self) -> bool {
        // Check if the fqdn ends with .local(.)
        // This indicates a special, local-only top level domain
        if let Some(tld) = self.data.last() {
            if let Ok(tld) = std::str::from_utf8(tld.as_slice()) {
                return tld == "local";
            }
        }
        false
    }

    pub fn is_root(&self) -> bool {
        // Root simply means "" or "." as fully-qualified domain name
        self.is_empty() || self.data.iter().all(|sub| sub.is_empty())
    }

    pub fn append_label(&mut self, name: &str) {
        self.data.push(name.as_bytes().to_vec());
    }
}

impl Display for FQDN {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (idx, name_part) in self.iter().enumerate() {
            // SAFETY: Safe because the u8 in self.data are parsed from a &str in the constructor
            write!(f, "{}", unsafe { std::str::from_utf8_unchecked(name_part) })?;
            if idx + 1 != self.data.len() {
                write!(f, ".")?;
            }
        }
        Ok(())
    }
}

impl IntoIterator for FQDN {
    type Item = Vec<u8>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a> IntoIterator for &'a FQDN {
    type Item = &'a Vec<u8>;
    type IntoIter = std::slice::Iter<'a, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut FQDN {
    type Item = &'a mut Vec<u8>;
    type IntoIter = std::slice::IterMut<'a, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl From<&str> for FQDN {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<&[&str]> for FQDN {
    fn from(value: &[&str]) -> Self {
        let data = value
            .iter()
            .map(|str_part| str_part.as_bytes().to_vec())
            .collect();
        Self { data }
    }
}

impl From<Vec<Vec<u8>>> for FQDN {
    fn from(data: Vec<Vec<u8>>) -> Self {
        Self { data }
    }
}

impl From<&[Vec<u8>]> for FQDN {
    fn from(data: &[Vec<u8>]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for FQDN {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer) -> Result<Self, Self::Error> {
        buffer.extract_fqdn()
    }
}

impl ByteConvertible for FQDN {
    #[inline]
    fn byte_size(&self) -> usize {
        // Initial value is set to 1 to represent the mandatory termination byte '0' that is always
        // present even for empty FQDNs. For every non-empty label of the FQDN we add the number of
        // the labels characters and one extra byte to represent the length of the label to the
        // accumulator
        self.iter().fold(1, |acc, label| {
            acc + if !label.is_empty() {
                1 + label.len()
            } else {
                0
            }
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        for name_part in self.iter() {
            if !name_part.is_empty() {
                buffer.push(name_part.len() as u8);
                buffer.extend_from_slice(name_part);
            }
        }
        buffer.push(0);

        buffer
    }
}

impl CompressedByteConvertible for FQDN {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, mut offset: usize) -> usize {
        let mut size = 0;
        for i in 0..self.data.len() {
            let remaining_fqdn = &self.data[i..];
            let remaining_hash = hash_fqdn(remaining_fqdn);

            if let Some(_pointer) = names.get(&remaining_hash) {
                // Found remaining match so we only add pointer length to the size
                size += 2;
                return size;
            } else {
                names.insert(remaining_hash, offset);
                offset += self.data[i].len() + 1;
                size += self.data[i].len() + 1;
            }
        }

        // Add 0 delimiter to size
        size + 1
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, mut offset: usize) -> Vec<u8> {
        let mut buffer = Vec::new();

        for i in 0..self.data.len() {
            let remaining_fqdn = &self.data[i..];
            let remaining_hash = hash_fqdn(remaining_fqdn);

            if let Some(pointer) = names.get(&remaining_hash) {
                let compressed_name = (*pointer as u16 | COMPRESSION_MASK_U16).to_be_bytes();
                buffer.extend_from_slice(&compressed_name);
                return buffer;
            } else {
                buffer.push(self.data[i].len() as u8);
                buffer.extend_from_slice(&self.data[i]);

                names.insert(remaining_hash, offset);
                offset += self.data[i].len() + 1;
            }
        }

        // Add 0 delimiter to buffer
        buffer.push(0);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::FQDN;

    #[test]
    fn fqdn_link_local() {
        let local = FQDN::new("_airplay._tcp.local");
        let non_local = FQDN::new("google.com");

        assert_eq!(local.is_link_local(), true);
        assert_eq!(non_local.is_link_local(), false);
    }

    #[test]
    fn parse_root() {
        use crate::ByteConvertible;

        let string_repr = ".";
        let fqdn = FQDN::from(string_repr);

        assert_eq!(fqdn.byte_size(), 1);
        assert_eq!(fqdn.to_bytes(), vec![0]);
        assert_eq!(fqdn.to_string(), String::default());
        assert_eq!(fqdn.is_root(), true);

        let string_repr = "";
        let fqdn = FQDN::from(string_repr);

        assert_eq!(fqdn.byte_size(), 1);
        assert_eq!(fqdn.to_bytes(), vec![0]);
        assert_eq!(fqdn.to_string(), String::default());
        assert_eq!(fqdn.is_root(), true);
    }

    #[test]
    fn build_root() {
        let fqdn = FQDN::new(".");
        assert_eq!(fqdn.to_string(), "");

        let fqdn = FQDN::new("");
        assert_eq!(fqdn.to_string(), "");
    }

    #[test]
    fn ordering() {
        let a = FQDN::new("google.com");
        let b = FQDN::new("www.google.com");
        let c = FQDN::new("aaa.de");
        let d = FQDN::new("google.de");
        let e = a.clone();

        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(a.cmp(&c), Ordering::Greater);
        assert_eq!(a.cmp(&d), Ordering::Less);
        assert_eq!(a.cmp(&e), Ordering::Equal);
    }
}
