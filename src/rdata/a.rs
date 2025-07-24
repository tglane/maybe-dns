use std::convert::{From, TryFrom};
use std::net::Ipv4Addr;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The RDATA section of an A line in a master file is an Internet address expressed as
/// four decimal numbers separated by dots without any imbedded spaces (e.g., "10.2.0.52"
/// or "192.0.5.6").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct A(Ipv4Addr);

impl A {
    pub fn new(addr: Ipv4Addr) -> Self {
        Self(addr)
    }

    pub fn inner(&self) -> &Ipv4Addr {
        &self.0
    }

    pub fn inner_mut(&mut self) -> &mut Ipv4Addr {
        &mut self.0
    }

    pub fn into_inner(self) -> Ipv4Addr {
        self.0
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for A {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self(Ipv4Addr::from(buffer.extract_u32()?)))
    }
}

impl RData for A {
    fn record_type(&self) -> RecordType {
        RecordType::A
    }

    fn into_record_data(self) -> RecordData {
        RecordData::A(self)
    }
}

impl ByteConvertible for A {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.octets().to_vec()
    }
}

impl From<A> for u32 {
    fn from(value: A) -> Self {
        u32::from(value.0)
    }
}

impl From<u32> for A {
    fn from(value: u32) -> Self {
        Self(Ipv4Addr::from(value))
    }
}

impl From<Ipv4Addr> for A {
    fn from(value: Ipv4Addr) -> Self {
        Self(value)
    }
}

impl TryFrom<&str> for A {
    type Error = std::net::AddrParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(value.parse::<Ipv4Addr>()?))
    }
}
