use std::convert::{From, TryFrom};
use std::net::Ipv6Addr;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// A record type is defined to store a host's IPv6 address.  A host that
/// has more than one IPv6 address must have more than one such record.
/// The AAAA resource record type is a record specific to the Internet
/// class that stores a single IPv6 address.
/// The IANA assigned value of the type is 28 (decimal).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aaaa(Ipv6Addr);

impl Aaaa {
    pub fn new(addr: Ipv6Addr) -> Self {
        Self(addr)
    }

    pub fn inner(&self) -> &Ipv6Addr {
        &self.0
    }

    pub fn inner_mut(&mut self) -> &mut Ipv6Addr {
        &mut self.0
    }

    pub fn into_inner(self) -> Ipv6Addr {
        self.0
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Aaaa {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self(Ipv6Addr::from(u128::from_be_bytes(
            buffer.extract_bytes(16)?.try_into()?,
        ))))
    }
}

impl RData for Aaaa {
    fn record_type(&self) -> RecordType {
        RecordType::AAAA
    }

    fn into_record_data(self) -> RecordData {
        RecordData::AAAA(self)
    }
}

impl ByteConvertible for Aaaa {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<u128>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.octets().to_vec()
    }
}

impl From<&Aaaa> for u128 {
    fn from(value: &Aaaa) -> Self {
        u128::from(value.0)
    }
}

impl From<u128> for Aaaa {
    fn from(value: u128) -> Self {
        Self(Ipv6Addr::from(value))
    }
}

impl From<Ipv6Addr> for Aaaa {
    fn from(value: Ipv6Addr) -> Self {
        Self(value)
    }
}

impl TryFrom<&str> for Aaaa {
    type Error = std::net::AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(value.parse::<Ipv6Addr>()?))
    }
}
