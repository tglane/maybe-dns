use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// A CAA RR contains a single Property consisting of a tag‑value pair.
/// An FQDN MAY have multiple CAA RRs associated with it, and a given
/// Property Tag MAY be specified more than once across those RRs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caa {
    /// If the value is set to "1", the Property is critical. A CA MUST NOT
    /// issue certificates for any FQDN if the Relevant RRset for that FQDN
    /// contains a CAA critical Property for an unknown or unsupported
    /// Property Tag.
    pub issuer_critical: bool,

    /// The Property identifier represented by a sequence of ASCII characters.
    pub tag: String,

    /// A sequence of octets representing the Property Value. Property Values
    /// are encoded as binary values and MAY employ sub‑formats
    pub value: Vec<u8>,
}

impl Caa {
    pub fn new(issuer_critical: bool, tag: String, value: Vec<u8>) -> Self {
        Self {
            issuer_critical,
            tag,
            value,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Caa {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let flags = buffer.extract_u8()?;
        let tag_len = buffer.extract_u8()?;

        if tag_len == 0 {
            return Err(DnsError::InvalidPacketData);
        }

        let tag = String::from_utf8_lossy(buffer.extract_bytes(tag_len as usize)?).to_string();
        let value = buffer.extract_bytes(buffer.remaining())?.to_vec();

        Ok(Self {
            issuer_critical: (flags & 0b10000000) != 0,
            tag,
            value,
        })
    }
}

impl RData for Caa {
    fn record_type(&self) -> RecordType {
        RecordType::CAA
    }

    fn into_record_data(self) -> RecordData {
        RecordData::CAA(self)
    }
}

impl ByteConvertible for Caa {
    fn byte_size(&self) -> usize {
        (2 * std::mem::size_of::<u8>()) + self.value.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.push((self.issuer_critical as u8) << 7);
        buff.push(self.tag.len() as u8);
        buff.extend_from_slice(self.tag.as_bytes());
        buff.extend_from_slice(&self.value);
        buff
    }
}
