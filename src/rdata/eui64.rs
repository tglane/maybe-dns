use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The EUI64 record (RR) is used to store a single EUI-64
/// address in the DNS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Eui64([u8; 8]);

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Eui64 {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self(buffer.extract_bytes(8)?.try_into()?))
    }
}

impl RData for Eui64 {
    fn record_type(&self) -> RecordType {
        RecordType::EUI64
    }

    fn into_record_data(self) -> RecordData {
        RecordData::EUI64(self)
    }
}

impl ByteConvertible for Eui64 {
    fn byte_size(&self) -> usize {
        8
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
