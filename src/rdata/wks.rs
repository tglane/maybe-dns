use std::convert::TryFrom;
use std::net::Ipv4Addr;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The WKS record is used to describe the well known services supported by
/// a particular protocol on a particular internet address. The PROTOCOL
/// field specifies an IP protocol number, and the bit map has one bit per
/// port of the specified protocol. The first bit corresponds to port 0,
/// the second to port 1, etc. If the bit map does not include a bit for a
/// protocol of interest, that bit is assumed zero. The appropriate values
/// and mnemonics for ports and protocols are specified in [RFC-1010].
///
/// For example, if PROTOCOL=TCP (6), the 26th bit corresponds to TCP port
/// 25 (SMTP). If this bit is set, a SMTP server should be listening on TCP
/// port 25; if zero, SMTP service is not supported on the specified
/// address.
///
/// The purpose of WKS RRs is to provide availability information for
/// servers for TCP and UDP. If a server supports both TCP and UDP, or has
/// multiple Internet addresses, then multiple WKS RRs are used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wks {
    /// An 32 bit Internet address
    pub address: Ipv4Addr,

    /// An 8 bit IP protocol number
    pub protocol: u8,

    /// A variable length bit map. The bit map must be a
    /// multiple of 8 bits long.
    pub bitmap: Vec<u8>,
}

impl Wks {
    pub fn new(address: Ipv4Addr, protocol: u8, bitmap: Vec<u8>) -> Self {
        Self {
            address,
            protocol,
            bitmap,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Wks {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            address: Ipv4Addr::from(buffer.extract_u32()?),
            protocol: buffer.extract_u8()?,
            bitmap: buffer.extract_bytes(buffer.remaining())?.to_vec(),
        })
    }
}

impl RData for Wks {
    fn record_type(&self) -> RecordType {
        RecordType::WKS
    }

    fn into_record_data(self) -> RecordData {
        RecordData::WKS(self)
    }
}

impl ByteConvertible for Wks {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<u32>() + std::mem::size_of::<u8>() + self.bitmap.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.extend_from_slice(&self.address.octets());
        buf.push(self.protocol);
        buf.extend(self.bitmap.clone());
        buf
    }
}
