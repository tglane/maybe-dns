use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// A Canonical Name (CNAME) record is a type of resource record in the Domain
/// Name System (DNS) that maps one domain name (an alias) to another (the
/// canonical name).
///
/// This can prove convenient when running multiple services (like an FTP server
/// and a web server, each running on different ports) from a single IP address.
/// One can, for example, use CNAME records to point ftp.example.com and www.example.com
/// to the DNS entry for example.com, which in turn has an A record which points
/// to the IP address. Then, if the IP address ever changes, one only has to record
/// the change in one place within the network: in the DNS A record for example.com.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cname {
    pub cname: FQDN,
}

impl Cname {
    pub fn new(cname: FQDN) -> Self {
        Self { cname }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Cname {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            cname: buffer.extract_fqdn()?,
        })
    }
}

impl RData for Cname {
    fn record_type(&self) -> RecordType {
        RecordType::CNAME
    }

    fn into_record_data(self) -> RecordData {
        RecordData::CNAME(self)
    }
}

impl ByteConvertible for Cname {
    fn byte_size(&self) -> usize {
        self.cname.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.cname.to_bytes()
    }
}

impl CompressedByteConvertible for Cname {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        self.cname.byte_size_compressed(names, offset)
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        self.cname.to_bytes_compressed(names, offset)
    }
}
