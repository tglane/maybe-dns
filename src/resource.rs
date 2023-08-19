use std::convert::{TryFrom, TryInto};
use std::mem::size_of;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::record_data::RecordData;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl TryFrom<u16> for RecordClass {
    type Error = DnsError;

    fn try_from(number: u16) -> Result<Self, DnsError> {
        let number = number & 0b01111111_11111111;
        match number {
            1 => Ok(RecordClass::IN),
            2 => Ok(RecordClass::CS),
            3 => Ok(RecordClass::CH),
            4 => Ok(RecordClass::HS),
            _ => Err(DnsError::InvalidClass(number)),
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
    NSEC = 47,
}

impl RecordType {
    pub fn compression_allowed(&self) -> bool {
        match self {
            RecordType::A => false,
            RecordType::NS => true,
            RecordType::CNAME => true,
            RecordType::SOA => true,
            RecordType::NULL => false,
            RecordType::WKS => false,
            RecordType::PTR => true,
            RecordType::HINFO => false,
            RecordType::MINFO => true,
            RecordType::MX => true,
            RecordType::TXT => true,
            RecordType::AAAA => false,
            RecordType::SRV => true,
            RecordType::NSEC => true,
        }
    }
}

impl TryFrom<u16> for RecordType {
    type Error = DnsError;

    fn try_from(number: u16) -> Result<Self, DnsError> {
        match number {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            5 => Ok(RecordType::CNAME),
            6 => Ok(RecordType::SOA),
            10 => Ok(RecordType::NULL),
            11 => Ok(RecordType::WKS),
            12 => Ok(RecordType::PTR),
            13 => Ok(RecordType::HINFO),
            14 => Ok(RecordType::MINFO),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            28 => Ok(RecordType::AAAA),
            33 => Ok(RecordType::SRV),
            47 => Ok(RecordType::NSEC),
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

        println!("LEL: {:?} - {:?}", a_name, buffer.read_bytes(2)?);
        let a_type = buffer.extract_u16_as::<RecordType>()?;

        #[cfg(not(feature = "mdns"))]
        let a_class = buffer.extract_u16_as::<RecordClass>()?;
        #[cfg(feature = "mdns")]
        let (a_class, cache_flush) = {
            const MDNS_ENABLE_CACHE_FLUSH: u16 = 1 << 15;
            let bin_val = buffer.extract_u16()?;
            if bin_val & MDNS_ENABLE_CACHE_FLUSH > 0 {
                let class_val = bin_val & !MDNS_ENABLE_CACHE_FLUSH;
                (RecordClass::try_from(class_val)?, true)
            } else {
                (RecordClass::try_from(bin_val)?, false)
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
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class as u16));
        #[cfg(feature = "mdns")]
        {
            let fused_last_byte = if self.cache_flush {
                const MDNS_ENABLE_CACHE_FLUSH: u16 = 1 << 15;
                self.a_class as u16 | MDNS_ENABLE_CACHE_FLUSH
            } else {
                self.a_class as u16
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
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class as u16));
        #[cfg(feature = "mdns")]
        {
            let fused_last_byte = if self.cache_flush {
                const MDNS_UNICAST_RESPONSE: u16 = 1 << 15;
                self.a_class as u16 | MDNS_UNICAST_RESPONSE
            } else {
                self.a_class as u16
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
