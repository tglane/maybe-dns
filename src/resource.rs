use std::convert::{From, Into, TryFrom, TryInto};
use std::mem::size_of;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::record_data::RecordData;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecordClass {
    IN,
    CS,
    CH,
    HS,
    UdpPayloadSize(u16), // RFC 6891 eDNS OPT pseudo record
}

impl From<u16> for RecordClass {
    fn from(number: u16) -> Self {
        let number = number & 0b01111111_11111111;
        match number {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => Self::UdpPayloadSize(number),
        }
    }
}

impl Into<u16> for RecordClass {
    fn into(self) -> u16 {
        match self {
            Self::IN => 1,
            Self::CS => 2,
            Self::CH => 3,
            Self::HS => 4,
            Self::UdpPayloadSize(size) => size,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
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
    OPT = 41, // RFC 6891 eDNS OPT pseudo-record
    NSEC = 47,
}

impl RecordType {
    pub fn compression_allowed(&self) -> bool {
        match self {
            Self::A => false,
            Self::NS => true,
            Self::CNAME => true,
            Self::SOA => true,
            Self::NULL => false,
            Self::WKS => false,
            Self::PTR => true,
            Self::HINFO => false,
            Self::MINFO => true,
            Self::MX => true,
            Self::TXT => true,
            Self::AAAA => false,
            Self::SRV => true,
            Self::OPT => false,
            Self::NSEC => true,
        }
    }
}

impl TryFrom<u16> for RecordType {
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
            41 => Ok(Self::OPT),
            47 => Ok(Self::NSEC),
            _ => Err(DnsError::InvalidType(number)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRecord {
    pub(super) a_name: FQDN,
    pub(super) a_type: RecordType,
    #[cfg(feature = "mdns")]
    pub(super) cache_flush: bool,
    pub(super) a_class: RecordClass,
    pub(super) time_to_live: u32,
    pub(super) rdata: RecordData,
}

impl ResourceRecord {
    pub fn new(
        a_name: FQDN,
        a_type: RecordType,
        a_class: RecordClass,
        ttl: u32,
        rdata: RecordData,
    ) -> Self {
        ResourceRecord {
            a_name,
            a_type,
            #[cfg(feature = "mdns")]
            cache_flush: false,
            a_class,
            time_to_live: ttl,
            rdata,
        }
    }

    pub fn name(&self) -> &FQDN {
        &self.a_name
    }

    pub fn set_name(&mut self, name: FQDN) {
        self.a_name = name;
    }

    pub fn record_type(&self) -> &RecordType {
        &self.a_type
    }

    pub fn set_record_type(&mut self, record_type: RecordType) {
        self.a_type = record_type;
    }

    #[cfg(feature = "mdns")]
    pub fn cache_flush(&self) -> bool {
        self.cache_flush
    }

    #[cfg(feature = "mdns")]
    pub fn set_cache_flush(&mut self, flush: bool) {
        self.cache_flush = flush;
    }

    pub fn class(&self) -> &RecordClass {
        &self.a_class
    }

    pub fn set_class(&mut self, class: RecordClass) {
        self.a_class = class;
    }

    pub fn time_to_live(&self) -> u32 {
        self.time_to_live
    }

    pub fn set_time_to_live(&mut self, ttl: u32) {
        self.time_to_live = ttl;
    }

    pub fn data(&self) -> &RecordData {
        &self.rdata
    }

    pub fn set_data(&mut self, data: RecordData) {
        self.rdata = data;
    }

    pub fn data_raw(&self) -> Vec<u8> {
        self.rdata.to_bytes()
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for ResourceRecord {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let a_name = buffer.extract_fqdn()?;

        let a_type = buffer.extract_u16_as::<RecordType>()?;

        #[cfg(not(feature = "mdns"))]
        let a_class = RecordClass::from(buffer.extract_u16()?);
        #[cfg(feature = "mdns")]
        let (a_class, cache_flush) = {
            const MDNS_ENABLE_CACHE_FLUSH: u16 = 1 << 15;
            let bin_val = buffer.extract_u16()?;
            if bin_val & MDNS_ENABLE_CACHE_FLUSH > 0 {
                let class_val = bin_val & !MDNS_ENABLE_CACHE_FLUSH;
                (RecordClass::from(class_val), true)
            } else {
                (RecordClass::from(bin_val), false)
            }
        };

        let time_to_live = u32::from_be_bytes(buffer.extract_bytes(4)?.try_into()?);

        let data_len = buffer.extract_u16()?;

        let mut sub_buffer = buffer.sub(data_len as usize)?;
        let rdata = RecordData::from(a_type, &mut sub_buffer)?;

        buffer.advance(data_len as usize);

        Ok(ResourceRecord {
            a_name,
            a_type,
            #[cfg(feature = "mdns")]
            cache_flush,
            a_class,
            time_to_live,
            rdata,
        })
    }
}

impl ByteConvertible for ResourceRecord {
    fn byte_size(&self) -> usize {
        self.a_name.byte_size()
            + size_of::<u16>()
            + size_of::<u16>()
            + size_of::<u32>()
            + size_of::<u16>()
            + self.rdata.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        buffer.extend_from_slice(&self.a_name.to_bytes());
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_type as u16));

        #[cfg(not(feature = "mdns"))]
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class.into()));
        #[cfg(feature = "mdns")]
        {
            let fused_last_byte = if self.cache_flush {
                const MDNS_ENABLE_CACHE_FLUSH: u16 = 1 << 15;
                Into::<u16>::into(self.a_class) | MDNS_ENABLE_CACHE_FLUSH
            } else {
                Into::<u16>::into(self.a_class)
            };
            buffer.extend_from_slice(&u16::to_be_bytes(fused_last_byte));
        }

        buffer.extend_from_slice(&u32::to_be_bytes(self.time_to_live));

        buffer.extend_from_slice(&u16::to_be_bytes(self.rdata.byte_size() as u16));

        buffer.extend_from_slice(&self.rdata.to_bytes());

        buffer
    }
}

impl CompressedByteConvertible for ResourceRecord {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        offset: usize,
    ) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.a_name.to_bytes_compressed(names, offset));

        buffer.extend_from_slice(&u16::to_be_bytes(self.a_type as u16));

        #[cfg(not(feature = "mdns"))]
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class.into()));
        #[cfg(feature = "mdns")]
        {
            let fused_last_byte: u16 = if self.cache_flush {
                const MDNS_UNICAST_RESPONSE: u16 = 1 << 15;
                Into::<u16>::into(self.a_class) | MDNS_UNICAST_RESPONSE
            } else {
                Into::<u16>::into(self.a_class)
            };
            buffer.extend_from_slice(&u16::to_be_bytes(fused_last_byte));
        }

        buffer.extend_from_slice(&u32::to_be_bytes(self.time_to_live));

        let compressed_rdata = self
            .rdata
            .to_bytes_compressed(names, offset + buffer.len() + 2);
        buffer.extend_from_slice(&u16::to_be_bytes(compressed_rdata.len() as u16));

        buffer.extend_from_slice(&compressed_rdata);

        buffer
    }
}
