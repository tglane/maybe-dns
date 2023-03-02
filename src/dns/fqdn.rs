use std::convert::{From, TryFrom};

use super::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use super::util::hash_bytes;
use super::DnsError;
use super::{COMPRESSION_MASK, COMPRESSION_MASK_U16};

#[derive(Clone, Debug)]
pub struct FQDN {
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
        let mut name = String::new();

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

impl CompressedByteConvertible for FQDN {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        mut offset: usize,
    ) -> Vec<u8> {
        let mut buffer = Vec::new();
        let flattend = self.to_bytes();

        let mut start_idx = 0;
        while start_idx < flattend.len() {
            let end_idx = start_idx + flattend[start_idx] as usize;
            let name_part = &flattend[start_idx..=end_idx];
            let remaining_hash = hash_bytes(&flattend[start_idx..]);

            if let Some(compressed_offset) = names.get(&remaining_hash) {
                let compressed_name =
                    (*compressed_offset as u16 | COMPRESSION_MASK_U16).to_be_bytes();
                buffer.extend_from_slice(&compressed_name);
                return buffer;
            } else {
                buffer.extend_from_slice(&name_part);
                names.insert(remaining_hash, offset);
                offset += name_part.len();
            }

            start_idx += flattend[start_idx] as usize + 1;
        }

        buffer
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

impl TryFrom<&[u8]> for FQDN {
    type Error = DnsError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let mut pos = 0_usize;
        let mut data = Vec::<Vec<u8>>::new();

        loop {
            if pos >= 255 || pos >= buffer.len() {
                return Err(DnsError::LengthViolation);
            }

            let len = buffer[pos];
            pos += 1;
            if len & COMPRESSION_MASK == COMPRESSION_MASK {
                return Err(DnsError::UnresolveableCompressionPointer);
            } else if pos + len as usize > buffer.len() {
                return Err(DnsError::LengthViolation);
            } else if len == 0 {
                break;
            }

            data.push(buffer[pos..pos + len as usize].to_vec());
            pos += len as usize;
        }

        Ok(Self { data })
    }
}
