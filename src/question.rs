use std::collections::HashMap;
use std::convert::TryFrom;
use std::mem::size_of;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;

/// Class type for question sections of dns packets. This is a superset of `RecordClass` with some
/// additional values specifically for question records.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QClass {
    // General RecordClass classes
    /// Internet
    IN = 1,
    /// CSNET (obsolete - used only for examples in obsolete RFCs)
    CS = 2,
    /// CHAOS
    CH = 3,
    /// Hesiod
    HS = 4,

    // Unique class for Question records
    NONE = 254,
    /// Matches any type.
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

/// Type field for question records. This is a superset of `RecordClass`.
/// This indicates which record type is stored in the record data section of the record.
/// Each `QType` corresponds with a type in `crate::rdata`
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QType {
    // General RecordType types
    A = 1,      // RFC 1035
    NS = 2,     // RFC 1035
    CNAME = 5,  // RFC 1035
    SOA = 6,    // RFC 1035
    NULL = 10,  // RFC 1035
    WKS = 11,   // RFC 1035
    PTR = 12,   // RFC 1035
    HINFO = 13, // RFC 1035
    MINFO = 14, // RFC 1035
    MX = 15,    // RFC 1035
    TXT = 16,   // RFC 1035
    AAAA = 28,  // RFC 3596
    LOC = 29,   // RFC 1876
    SRV = 33,   // RFC 2782
    NAPTR = 35, // RFC 3404
    OPT = 41,   // RFC 6891
    APL = 42,   // RFC 3123
    #[cfg(feature = "dnssec")]
    DS = 43, // RFC 4034
    SSHFP = 44, // RFC 4255
    IPSECKEY = 45, // RFC 4025
    #[cfg(feature = "dnssec")]
    RRSIG = 46, // RFC 4034
    #[cfg(feature = "dnssec")]
    NSEC = 47, // RFC 4034
    #[cfg(feature = "dnssec")]
    DNSKEY = 48, // RFC 4034
    DHCID = 49, // RFC 4701
    TLSA = 52,  // RFC 6698
    HIP = 55,   // RFC 8005
    #[cfg(feature = "dnssec")]
    CDS = 59, // RFC 7344
    #[cfg(feature = "dnssec")]
    CDNSKEY = 60, // RFC 7344
    OPENPGPKEY = 61, // RFC 7929
    CSYNC = 62, // RFC 7477
    SVCB = 64,  // RFC 9460
    EUI48 = 108, // RFC 7043
    EUI64 = 109, // RFC 7043
    TKEY = 249, // RFC 2930
    TSIG = 250, // RFC 8945
    URI = 256,  // RFC 7553
    CAA = 257,  // RFC 8659

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
            29 => Ok(Self::LOC),
            33 => Ok(Self::SRV),
            35 => Ok(Self::NAPTR),
            41 => Ok(Self::OPT),
            42 => Ok(Self::APL),
            #[cfg(feature = "dnssec")]
            43 => Ok(Self::DS),
            44 => Ok(Self::SSHFP),
            45 => Ok(Self::IPSECKEY),
            #[cfg(feature = "dnssec")]
            46 => Ok(Self::RRSIG),
            #[cfg(feature = "dnssec")]
            47 => Ok(Self::NSEC),
            #[cfg(feature = "dnssec")]
            48 => Ok(Self::DNSKEY),
            49 => Ok(Self::DHCID),
            52 => Ok(Self::TLSA),
            55 => Ok(Self::HIP),
            61 => Ok(Self::OPENPGPKEY),
            62 => Ok(Self::CSYNC),
            64 => Ok(Self::SVCB),
            108 => Ok(Self::EUI48),
            109 => Ok(Self::EUI64),
            249 => Ok(Self::TKEY),
            250 => Ok(Self::TSIG),
            256 => Ok(Self::URI),
            257 => Ok(Self::CAA),

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
            QType::LOC => 29,
            QType::SRV => 33,
            QType::NAPTR => 35,
            QType::OPT => 41,
            QType::APL => 42,
            #[cfg(feature = "dnssec")]
            QType::DS => 43,
            QType::SSHFP => 44,
            QType::IPSECKEY => 45,
            #[cfg(feature = "dnssec")]
            QType::RRSIG => 46,
            #[cfg(feature = "dnssec")]
            QType::NSEC => 47,
            #[cfg(feature = "dnssec")]
            QType::DNSKEY => 48,
            QType::DHCID => 49,
            QType::TLSA => 52,
            QType::HIP => 55,
            #[cfg(feature = "dnssec")]
            QType::CDS => 59,
            #[cfg(feature = "dnssec")]
            QType::CDNSKEY => 60,
            QType::OPENPGPKEY => 61,
            QType::CSYNC => 62,
            QType::SVCB => 64,
            QType::EUI48 => 108,
            QType::EUI64 => 109,
            QType::TKEY => 249,
            QType::TSIG => 250,
            QType::URI => 256,
            QType::CAA => 257,

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

/// Describes a question to a name server that is stored in the questions array of a dns packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// A domain name of the requested resource.
    pub(super) q_name: FQDN,
    /// Type of the record data of the expected response.
    pub(super) q_type: QType,
    /// Class of the record of the expected response.
    pub(super) q_class: QClass,
    /// States if the question requires only unicast responses. This is only valid for mDNS requets.
    #[cfg(feature = "mdns")]
    pub(super) unicast_response: bool,
}

impl Question {
    /// Create a new `Question` instance with a given domain name, type and class.
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
