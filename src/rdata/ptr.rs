use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// PTR records cause no additional section processing.  These RRs are used
/// in special domains to point to some other location in the domain space.
/// These records are simple data, and don't imply any special processing
/// similar to that performed by CNAME, which identifies aliases.  See the
/// description of the IN-ADDR.ARPA domain for an example.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ptr(FQDN);

impl Ptr {
    pub fn new(ptr_dname: FQDN) -> Self {
        Self(ptr_dname)
    }

    pub fn inner(&self) -> &FQDN {
        &self.0
    }

    pub fn inner_mut(&mut self) -> &mut FQDN {
        &mut self.0
    }

    pub fn into_inner(self) -> FQDN {
        self.0
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Ptr {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self(buffer.extract_fqdn()?))
    }
}

impl RData for Ptr {
    fn record_type(&self) -> RecordType {
        RecordType::PTR
    }

    fn into_record_data(self) -> RecordData {
        RecordData::PTR(self)
    }
}

impl ByteConvertible for Ptr {
    fn byte_size(&self) -> usize {
        self.0.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl CompressedByteConvertible for Ptr {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        self.0.byte_size_compressed(names, offset)
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        self.0.to_bytes_compressed(names, offset)
    }
}
