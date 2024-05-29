use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// A start of authority record (abbreviated as SOA record) is a type of resource record in the
/// Domain Name System (DNS) containing administrative information about the zone, especially
/// regarding zone transfers. The SOA record format is specified in RFC 1035.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Soa {
    /// The <domain-name> of the name server that was the
    /// original or primary source of data for this zone.
    pub mname: FQDN,

    /// A <domain-name> which specifies the mailbox of the
    /// person responsible for this zone.
    pub rname: FQDN,

    /// The unsigned 32 bit version number of the original copy
    /// of the zone.  Zone transfers preserve this value.  This
    /// value wraps and should be compared using sequence space
    /// arithmetic.
    pub serial: u32,

    /// A 32 bit time interval before the zone should be
    /// refreshed.
    pub refresh: u32,

    /// A 32 bit time interval that should elapse before a
    /// failed refresh should be retried.
    pub retry: u32,

    /// A 32 bit time value that specifies the upper limit on
    /// the time interval that can elapse before the zone is no
    /// longer authoritative.
    pub expire: u32,

    /// The unsigned 32 bit minimum TTL field that should be
    /// exported with any RR from this zone.
    pub minimum: u32,
}

impl Soa {
    pub fn new(
        mname: FQDN,
        rname: FQDN,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Soa {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            mname: buffer.extract_fqdn()?,
            rname: buffer.extract_fqdn()?,
            serial: buffer.extract_u32()?,
            refresh: buffer.extract_u32()?,
            retry: buffer.extract_u32()?,
            expire: buffer.extract_u32()?,
            minimum: buffer.extract_u32()?,
        })
    }
}

impl RData for Soa {
    fn record_type(&self) -> RecordType {
        RecordType::SOA
    }

    fn into_record_data(self) -> RecordData {
        RecordData::SOA(self)
    }
}

impl ByteConvertible for Soa {
    fn byte_size(&self) -> usize {
        self.mname.byte_size() + self.rname.byte_size() + (std::mem::size_of::<u32>() * 5)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.extend(self.mname.to_bytes());
        buf.extend(self.rname.to_bytes());
        buf.extend(u32::to_be_bytes(self.serial));
        buf.extend(u32::to_be_bytes(self.refresh));
        buf.extend(u32::to_be_bytes(self.retry));
        buf.extend(u32::to_be_bytes(self.expire));
        buf.extend(u32::to_be_bytes(self.minimum));
        buf
    }
}

impl CompressedByteConvertible for Soa {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        self.mname.byte_size_compressed(names, offset)
            + self.rname.byte_size_compressed(names, offset)
            + (std::mem::size_of::<u32>() * 5)
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.mname.to_bytes_compressed(names, offset));
        buf.extend(self.rname.to_bytes_compressed(names, offset + buf.len()));
        buf.extend(u32::to_be_bytes(self.serial));
        buf.extend(u32::to_be_bytes(self.refresh));
        buf.extend(u32::to_be_bytes(self.retry));
        buf.extend(u32::to_be_bytes(self.expire));
        buf.extend(u32::to_be_bytes(self.minimum));
        buf
    }
}
