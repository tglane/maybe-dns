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
    pub(super) q_name: FQDN,
    pub(super) q_type: QType,
    pub(super) q_class: QClass,
    #[cfg(feature = "mdns")]
    pub(super) unicast_response: bool,
}

impl Question {
    pub fn new(q_name: FQDN, q_type: QType, q_class: QClass) -> Self {
        Question {
            q_name,
            q_type,
            q_class,
            #[cfg(feature = "mdns")]
            unicast_response: false,
        }
    }

    pub fn name(&self) -> &FQDN {
        &self.q_name
    }

    pub fn set_name(&mut self, name: FQDN) {
        self.q_name = name;
    }

    pub fn query_type(&self) -> &QType {
        &self.q_type
    }

    pub fn set_query_type(&mut self, query_type: QType) {
        self.q_type = query_type;
    }

    pub fn class(&self) -> &QClass {
        &self.q_class
    }

    pub fn set_class(&mut self, class: QClass) {
        self.q_class = class;
    }

    #[cfg(feature = "mdns")]
    pub fn unicast_response(&self) -> bool {
        self.unicast_response
    }

    #[cfg(feature = "mdns")]
    pub fn set_unicast_response(&mut self, unicast: bool) {
        self.unicast_response = unicast;
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

        #[cfg(not(feature = "mdns"))]
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_class as u16));
        #[cfg(feature = "mdns")]
        {
            let fused_last_byte = if self.unicast_response {
                const MDNS_UNICAST_RESPONSE: u16 = 1 << 15;
                self.q_class as u16 | MDNS_UNICAST_RESPONSE
            } else {
                self.q_class as u16
            };
            buffer.extend_from_slice(&u16::to_be_bytes(fused_last_byte));
        }

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

        #[cfg(not(feature = "mdns"))]
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_class as u16));
        #[cfg(feature = "mdns")]
        {
            let fused_last_byte = if self.unicast_response {
                const MDNS_UNICAST_RESPONSE: u16 = 1 << 15;
                self.q_class as u16 | MDNS_UNICAST_RESPONSE
            } else {
                self.q_class as u16
            };

            buffer.extend_from_slice(&u16::to_be_bytes(fused_last_byte));
        }

        buffer
    }
}
