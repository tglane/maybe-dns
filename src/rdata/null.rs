use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// Anything at all may be in the RDATA field so long as it is 65535 octets
/// or less.
/// NULL records cause no additional section processing.  NULL RRs are not
/// allowed in master files.  NULLs are used as placeholders in some
/// experimental extensions of the DNS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Null {
    pub anything: Vec<u8>,
}

impl Null {
    pub fn new(anything: Vec<u8>) -> Self {
        Self { anything }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Null {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            anything: buffer.extract_bytes(buffer.remaining())?.to_vec(),
        })
    }
}

impl RData for Null {
    fn record_type(&self) -> RecordType {
        RecordType::NULL
    }

    fn into_record_data(self) -> RecordData {
        RecordData::NULL(self)
    }
}

impl ByteConvertible for Null {
    fn byte_size(&self) -> usize {
        self.anything.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.anything.clone()
    }
}
