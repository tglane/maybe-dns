use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// TXT RRs are used to hold descriptive text. The semantics of the text
/// depends on the domain where it is found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Txt(pub Vec<String>);

impl Txt {
    pub fn new(data: Vec<String>) -> Self {
        Self(data)
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Txt {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let mut txt_store = Vec::<String>::new();
        while buffer.remaining() > 0 {
            let txt_size = buffer.extract_u8()?;
            txt_store.push(
                String::from_utf8_lossy(buffer.extract_bytes(txt_size as usize)?).to_string(),
            );
        }
        Ok(Self(txt_store))
    }
}

impl RData for Txt {
    fn record_type(&self) -> RecordType {
        RecordType::TXT
    }

    fn into_record_data(self) -> RecordData {
        RecordData::TXT(self)
    }
}

impl ByteConvertible for Txt {
    fn byte_size(&self) -> usize {
        self.0.iter().fold(0, |acc, elem| acc + elem.len() + 1)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().fold(Vec::new(), |mut buff, elem| {
            let txt_bin = elem.as_bytes();
            buff.push(txt_bin.len() as u8);
            buff.extend_from_slice(txt_bin);
            buff
        })
    }
}
