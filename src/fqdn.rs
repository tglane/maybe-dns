use std::convert::{From, TryFrom};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::util::hash_fqdn;
use crate::COMPRESSION_MASK_U16;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FQDN {
    // TODO: Store data in a flattend representation (Vec<u8> instead of Vec<Vec<u8>>)
    data: Vec<Vec<u8>>,
}

impl FQDN {
    pub fn new(name: &str) -> Self {
        let mut data = Vec::<Vec<u8>>::new();

        let mut part_start = 0;
        for idx in 0..name.len() + 1 {
            if idx == name.len() || name.as_bytes()[idx] == '.' as u8 {
                data.push(name[part_start..idx].as_bytes().to_vec());
                part_start = idx + 1;
            }
        }

        Self { data }
    }

    pub fn to_string(&self) -> String {
        if self.is_root() {
            return String::from(".");
        }

        let mut name = String::with_capacity(self.len());
        for (idx, name_part) in self.iter().enumerate() {
            // Safe because the u8 in self.data are parsed from a &str in the constructor
            name.push_str(unsafe { std::str::from_utf8_unchecked(name_part) });
            if idx + 1 != self.data.len() {
                name.push('.');
            }
        }

        name
    }

    pub fn len(&self) -> usize {
        self.iter().fold(0, |acc, name_part| {
            acc + name_part.len() + if acc == 0 { 0 } else { 1 }
        })
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
        return false;
    }

    pub fn is_root(&self) -> bool {
        // Root simply means an empty fqdn
        self.data.len() == 0
    }

    pub fn append_label(&mut self, name: &str) {
        self.data.push(name.as_bytes().to_vec());
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

impl ByteConvertible for FQDN {
    fn byte_size(&self) -> usize {
        self.len() + 2
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        for name_part in self.iter() {
            buffer.push(name_part.len() as u8);
            buffer.extend_from_slice(&name_part);
        }
        buffer.push(0);

        buffer
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
            .collect::<Vec<Vec<u8>>>();
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
        Self { data: data.to_vec() }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for FQDN {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer) -> Result<Self, Self::Error> {
        buffer.extract_fqdn()
    }
}

impl CompressedByteConvertible for FQDN {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        mut offset: usize,
    ) -> Vec<u8> {
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

        buffer.push(0);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::FQDN;

    #[test]
    fn fqdn_link_local() {
        let local = FQDN::new("_airplay._tcp.local");
        let non_local = FQDN::new("google.com");

        assert_eq!(local.is_link_local(), true);
        assert_eq!(non_local.is_link_local(), false);
    }
}
