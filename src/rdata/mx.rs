use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// MX records cause type A additional section processing for the host
/// specified by EXCHANGE.  The use of MX RRs is explained in detail in
/// [RFC-974].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mx {
    /// A 16 bit integer which specifies the preference given to
    /// this RR among others at the same owner.  Lower values
    /// are preferred.
    pub preference: u16,

    /// A <domain-name> which specifies a host willing to act as
    /// a mail exchange for the owner name.
    pub exchange: FQDN,
}

impl Mx {
    pub fn new(preference: u16, exchange: FQDN) -> Self {
        Self {
            preference,
            exchange,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Mx {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            preference: buffer.extract_u16()?,
            exchange: buffer.extract_fqdn()?,
        })
    }
}

impl RData for Mx {
    fn record_type(&self) -> RecordType {
        RecordType::MX
    }

    fn into_record_data(self) -> RecordData {
        RecordData::MX(self)
    }
}

impl ByteConvertible for Mx {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<u16>() + self.exchange.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        buffer.extend(u16::to_be_bytes(self.preference));
        buffer.append(&mut self.exchange.to_bytes());
        buffer
    }
}

impl CompressedByteConvertible for Mx {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        std::mem::size_of::<u16>() + self.exchange.byte_size_compressed(names, offset)
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(u16::to_be_bytes(self.preference));
        buffer.extend_from_slice(&self.exchange.to_bytes_compressed(names, offset + 2));
        buffer
    }
}
