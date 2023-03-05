use std::convert::TryFrom;
use std::mem::size_of;

use super::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use super::error::DnsError;
use super::fqdn::FQDN;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QClass {
    // General RecordClass classes
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,

    // Unique class for Question records
    NONE = 254,
    ANY = 255,
}

impl TryFrom<u16> for QClass {
    type Error = DnsError;

    fn try_from(number: u16) -> Result<Self, DnsError> {
        let number = number & 0b01111111_11111111;
        match number {
            1 => Ok(QClass::IN),
            2 => Ok(QClass::CS),
            3 => Ok(QClass::CH),
            4 => Ok(QClass::HS),
            254 => Ok(QClass::NONE),
            255 => Ok(QClass::ANY),
            _ => Err(DnsError::InvalidClass(number)),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QType {
    // General RecordType types
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NSEC = 47,

    // Unique types for Question records
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,
}

impl TryFrom<u16> for QType {
    type Error = DnsError;

    fn try_from(number: u16) -> Result<Self, DnsError> {
        match number {
            1 => Ok(QType::A),
            2 => Ok(QType::NS),
            5 => Ok(QType::CNAME),
            6 => Ok(QType::SOA),
            10 => Ok(QType::NULL),
            11 => Ok(QType::WKS),
            12 => Ok(QType::PTR),
            13 => Ok(QType::HINFO),
            14 => Ok(QType::MINFO),
            15 => Ok(QType::MX),
            16 => Ok(QType::TXT),
            28 => Ok(QType::AAAA),
            33 => Ok(QType::SRV),
            47 => Ok(QType::NSEC),
            252 => Ok(QType::AXFR),
            253 => Ok(QType::MAILB),
            254 => Ok(QType::MAILA),
            255 => Ok(QType::ANY),
            _ => Err(DnsError::InvalidType(number)),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Question {
    pub q_name: FQDN,
    pub q_type: QType,
    pub q_class: QClass,
}

impl Question {
    pub fn new(q_name: FQDN, q_type: QType, q_class: QClass) -> Self {
        Question {
            q_name,
            q_type,
            q_class,
        }
    }
}

impl ByteConvertible for Question {
    fn byte_size(&self) -> usize {
        self.q_name.byte_size() + size_of::<u16>() + size_of::<u16>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer =
            Vec::with_capacity(self.q_name.byte_size() + size_of::<u16>() + size_of::<u16>());
        buffer.extend_from_slice(&self.q_name.to_bytes());
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_class as u16));
        buffer
    }
}

impl CompressedByteConvertible for Question {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        offset: usize,
    ) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.q_name.to_bytes_compressed(names, offset));
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_class as u16));
        buffer
    }
}
