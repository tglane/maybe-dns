use std::collections::HashMap;
use std::convert::TryFrom;
use std::mem::size_of;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;

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

impl From<QClass> for u16 {
    fn from(value: QClass) -> Self {
        match value {
            QClass::IN => 1,
            QClass::CS => 2,
            QClass::CH => 3,
            QClass::HS => 4,
            QClass::NONE => 254,
            QClass::ANY => 255,
        }
    }
}

impl ByteConvertible for QClass {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<u16>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        u16::to_be_bytes(u16::from(*self)).to_vec()
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
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            5 => Ok(Self::CNAME),
            6 => Ok(Self::SOA),
            10 => Ok(Self::NULL),
            11 => Ok(Self::WKS),
            12 => Ok(Self::PTR),
            13 => Ok(Self::HINFO),
            14 => Ok(Self::MINFO),
            15 => Ok(Self::MX),
            16 => Ok(Self::TXT),
            28 => Ok(Self::AAAA),
            33 => Ok(Self::SRV),
            47 => Ok(Self::NSEC),
            252 => Ok(Self::AXFR),
            253 => Ok(Self::MAILB),
            254 => Ok(Self::MAILA),
            255 => Ok(Self::ANY),
            _ => Err(DnsError::InvalidType(number)),
        }
    }
}

impl From<QType> for u16 {
    fn from(value: QType) -> Self {
        match value {
            QType::A => 1,
            QType::NS => 2,
            QType::CNAME => 5,
            QType::SOA => 6,
            QType::NULL => 10,
            QType::WKS => 11,
            QType::PTR => 12,
            QType::HINFO => 13,
            QType::MINFO => 14,
            QType::MX => 15,
            QType::TXT => 16,
            QType::AAAA => 28,
            QType::SRV => 33,
            QType::NSEC => 47,
            QType::AXFR => 252,
            QType::MAILB => 253,
            QType::MAILA => 254,
            QType::ANY => 255,
        }
    }
}

impl ByteConvertible for QType {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<u16>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        u16::to_be_bytes(u16::from(*self)).to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Question {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let q_name = buffer.extract_fqdn()?;

        let q_type = buffer.extract_u16_as::<QType>()?;

        #[cfg(not(feature = "mdns"))]
        let q_class = buffer.extract_u16_as::<QClass>()?;
        #[cfg(feature = "mdns")]
        let (q_class, unicast_response) = {
            const MDNS_UNICAST_RESPONSE: u16 = 1 << 15;
            let bin_val = buffer.extract_u16()?;
            if bin_val & MDNS_UNICAST_RESPONSE > 0 {
                (QClass::try_from(bin_val & !MDNS_UNICAST_RESPONSE)?, true)
            } else {
                (QClass::try_from(bin_val)?, false)
            }
        };

        Ok(Self {
            q_name,
            q_type,
            q_class,
            #[cfg(feature = "mdns")]
            unicast_response,
        })
    }
}

impl ByteConvertible for Question {
    fn byte_size(&self) -> usize {
        self.q_name.byte_size() + size_of::<u16>() + size_of::<u16>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.q_name.byte_size() + (2 * size_of::<u16>()));

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
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        self.q_name.byte_size_compressed(names, offset) + (2 * size_of::<u16>())
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
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
