use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// HINFO records are used to acquire general information about a host.  The
/// main use is for protocols such as FTP that can use special procedures
/// when talking between machines or operating systems of the same type.
///
/// Standard values for CPU and OS can be found in [RFC-1010].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hinfo {
    pub cpu: Vec<u8>,
    pub os: Vec<u8>,
}

impl Hinfo {
    pub fn new(cpu: Vec<u8>, os: Vec<u8>) -> Self {
        Self { cpu, os }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Hinfo {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            cpu: buffer.extract_character_string()?,
            os: buffer.extract_character_string()?,
        })
    }
}

impl RData for Hinfo {
    fn record_type(&self) -> RecordType {
        RecordType::HINFO
    }

    fn into_record_data(self) -> RecordData {
        RecordData::HINFO(self)
    }
}

impl ByteConvertible for Hinfo {
    fn byte_size(&self) -> usize {
        self.cpu.len() + self.os.len() + 2
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        buffer.push(self.cpu.len() as u8);
        buffer.extend_from_slice(&self.cpu);
        buffer.push(self.os.len() as u8);
        buffer.extend_from_slice(&self.os);
        buffer
    }
}
