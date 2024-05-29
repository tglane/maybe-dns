use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// NS records cause both the usual additional section processing to locate
/// a type A record, and, when used in a referral, a special search of the
/// zone in which they reside for glue information.
///
/// The NS RR states that the named host should be expected to have a zone
/// starting at owner name of the specified class.  Note that the class may
/// not indicate the protocol family which should be used to communicate
/// with the host, although it is typically a strong hint.  For example,
/// hosts which are name servers for either Internet (IN) or Hesiod (HS)
/// class information are normally queried using IN class protocols.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ns {
    pub nsdname: FQDN,
}

impl Ns {
    pub fn new(nsdname: FQDN) -> Self {
        Self { nsdname }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Ns {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            nsdname: buffer.extract_fqdn()?,
        })
    }
}

impl RData for Ns {
    fn record_type(&self) -> RecordType {
        RecordType::NS
    }

    fn into_record_data(self) -> RecordData {
        RecordData::NS(self)
    }
}

impl ByteConvertible for Ns {
    fn byte_size(&self) -> usize {
        self.nsdname.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.nsdname.to_bytes()
    }
}

impl CompressedByteConvertible for Ns {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        self.nsdname.byte_size_compressed(names, offset)
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        self.nsdname.to_bytes_compressed(names, offset)
    }
}
