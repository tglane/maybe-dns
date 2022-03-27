use std::mem::size_of;
use std::array::TryFromSliceError;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::util::ByteConvertible;
use super::fqdn::FQDN;
use super::error::DnsError;

#[derive(Copy, Clone, Debug)]
pub enum RecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    Unassigned,
}

impl RecordClass {
    pub fn from(number: u16) -> Self {
        let number = number & 0b01111111_11111111;
        match number {
            1 => RecordClass::IN,
            2 => RecordClass::CS,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => RecordClass::Unassigned,
        }
    }
}


#[derive(Copy, Clone, Debug)]
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
}

impl RecordType {
    pub fn from(number: u16) -> Result<Self, DnsError> {
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
             _ => Err(DnsError::InvalidType(number)),
        }
    }

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
        }
    }
}


#[derive(Clone, Debug)]
pub enum RecordData {
    A(Ipv4Addr),
    NS(FQDN),
    CNAME(FQDN),
    SOA {
        mname: FQDN,
        rname: FQDN,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    NULL(Vec<u8>),
    WKS {
        address: u32,
        protocol: u8,
        bitmap: Vec<u8>
    },
    PTR(FQDN),
    HINFO {
        cpu: Vec<u8>,
        os: Vec<u8>,
    },
    MINFO {
        rmailbx: FQDN,
        emailbx: FQDN,
    },
    MX {
        preference: u16,
        exchange: FQDN,
    },
    TXT(Vec<String>),
    AAAA(Ipv6Addr),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: FQDN,
    },
}

impl RecordData {
    pub fn from(rec_type: RecordType, buffer: &[u8]) -> Result<Self, DnsError> {
        Ok(match rec_type {
            RecordType::A => RecordData::A(Ipv4Addr::from(u32::from_be_bytes(buffer.try_into()?))),
            RecordType::NS => RecordData::NS(FQDN::from(buffer)),
            RecordType::CNAME => RecordData::CNAME(FQDN::from(buffer)),
            RecordType::SOA => RecordData::parse_soa(buffer)?,
            RecordType::NULL => RecordData::NULL(buffer.to_vec()),
            RecordType::WKS => RecordData::parse_wks(buffer)?,
            RecordType::PTR => RecordData::PTR(FQDN::from(buffer)),
            RecordType::HINFO => RecordData::parse_hinfo(buffer)?,
            RecordType::MINFO => RecordData::parse_minfo(buffer)?,
            RecordType::MX => RecordData::parse_mx(buffer)?,
            RecordType::TXT => RecordData::parse_txt(buffer),
            RecordType::AAAA => RecordData::AAAA(Ipv6Addr::from(u128::from_be_bytes(buffer.try_into()?))),
            RecordType::SRV => RecordData::parse_srv(buffer)?,
        })
    }

    fn parse_soa(buffer: &[u8]) -> Result<Self, TryFromSliceError> {
        let mname = FQDN::from(buffer);
        let rname = FQDN::from(&buffer[mname.byte_size()..]);
        let idx_advanced = rname.len();
        let serial = u32::from_be_bytes(buffer[idx_advanced..idx_advanced+4].try_into()?);
        let refresh = u32::from_be_bytes(buffer[idx_advanced+4..idx_advanced+8].try_into()?);
        let retry = u32::from_be_bytes(buffer[idx_advanced+8..idx_advanced+12].try_into()?);
        let expire = u32::from_be_bytes(buffer[idx_advanced+12..idx_advanced+16].try_into()?);
        let minimum = u32::from_be_bytes(buffer[idx_advanced+16..idx_advanced+20].try_into()?);

        Ok(RecordData::SOA { mname, rname, serial, refresh, retry, expire, minimum })
    }

    fn parse_wks(buffer: &[u8]) -> Result<Self, TryFromSliceError> {
        let address = u32::from_be_bytes(buffer[0..2].try_into()?);
        let protocol = buffer[2];
        let bitmap = buffer[3..].to_vec();

        Ok(RecordData::WKS { address, protocol, bitmap })
    }

    fn parse_hinfo(buffer: &[u8]) -> Result<Self, DnsError> {
        let cpu_len = buffer[0] as usize;
        let cpu = buffer[1..cpu_len].to_vec();
        let os_len = buffer[cpu_len+ 1] as usize;
        let os = buffer[cpu_len+2..cpu_len+2+os_len].to_vec();

        Ok(RecordData::HINFO { cpu, os })
    }

    fn parse_minfo(buffer: &[u8]) -> Result<Self, DnsError> {
        let rmailbx = FQDN::from(buffer);
        let emailbx = FQDN::from(&buffer[rmailbx.byte_size()..]);

        Ok(RecordData::MINFO { rmailbx, emailbx })
    }

    fn parse_mx(buffer: &[u8]) -> Result<Self, TryFromSliceError> {
        let preference = u16::from_be_bytes(buffer[0..2].try_into()?);
        let exchange = FQDN::from(&buffer[2..]);

        Ok(RecordData::MX { preference, exchange })
    }

    fn parse_txt(buffer: &[u8]) -> Self {
        let mut txt_store = Vec::<String>::new();
        let mut idx = 0;
        while idx < buffer.len() {
            let txt_size = buffer[idx];
            txt_store.push(String::from_utf8_lossy(&buffer[idx+1..idx+txt_size as usize+1]).to_string());
            idx += txt_size as usize + 1;
        }
        RecordData::TXT(txt_store)
    }

    fn parse_srv(buffer: &[u8]) -> Result<Self, TryFromSliceError> {
        let priority = u16::from_be_bytes(buffer[0..2].try_into()?);
        let weight = u16::from_be_bytes(buffer[2..4].try_into()?);
        let port = u16::from_be_bytes(buffer[4..6].try_into()?);
        let target = FQDN::from(&buffer[6..buffer.len()]);

        Ok(RecordData::SRV { priority, weight, port, target })
    }
}

impl ByteConvertible for RecordData {
    fn byte_size(&self) -> usize {
        match self {
            RecordData::A(_) => 4,
            RecordData::NS(ref name) => name.byte_size(),
            RecordData::CNAME(ref name) => name.byte_size(),
            RecordData::SOA { ref mname, ref rname, serial: _, refresh: _, retry: _, expire: _, minimum: _ } => {
                mname.len() + 2 + rname.len() + 2 + 4 + 4 + 4 + 4 + 4
            },
            RecordData::NULL(ref buffer) => buffer.len(),
            RecordData::WKS { address: _, protocol: _, ref bitmap } => 4 + 1 + bitmap.len(),
            RecordData::PTR(ref name) => name.byte_size(),
            RecordData::HINFO { ref cpu, ref os } => 2 + cpu.len() + os.len(),
            RecordData::MINFO { ref rmailbx, ref emailbx } => rmailbx.len() + 2 + emailbx.len() + 2,
            RecordData::MX { preference: _, ref exchange } => 2 + exchange.len() + 2,
            RecordData::TXT(ref store) => store.iter().fold(0, |acc, elem| acc + elem.len() + 1),
            RecordData::AAAA(_) => 16,
            RecordData::SRV { priority: _, weight: _, port: _, ref target } => 2 + 2 + 2 + target.len() + 2,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            RecordData::A(ref buffer) => buffer.octets().to_vec(),
            RecordData::NS(ref name) => name.to_bytes(),
            RecordData::CNAME(ref name) => name.to_bytes(),
            RecordData::SOA { ref mname, ref rname, ref serial, ref refresh, ref retry, ref expire, ref minimum  } => {
                let mut buffer = Vec::with_capacity(mname.byte_size() + rname.byte_size() + 64);
                buffer.extend_from_slice(&mname.to_bytes());
                buffer.extend_from_slice(&rname.to_bytes());
                buffer.extend_from_slice(&u32::to_be_bytes(*serial));
                buffer.extend_from_slice(&u32::to_be_bytes(*refresh));
                buffer.extend_from_slice(&u32::to_be_bytes(*retry));
                buffer.extend_from_slice(&u32::to_be_bytes(*expire));
                buffer.extend_from_slice(&u32::to_be_bytes(*minimum));
                buffer
            },
            RecordData::NULL(ref buffer) => buffer.clone(),
            RecordData::WKS { ref address, ref protocol, ref bitmap } => {
                let mut buffer = Vec::with_capacity(4 + 1 + bitmap.len());
                buffer.extend_from_slice(&u32::to_be_bytes(*address));
                buffer.extend_from_slice(&u8::to_be_bytes(*protocol));
                buffer.extend_from_slice(&bitmap);
                buffer
            },
            RecordData::PTR(ref name) => name.to_bytes(),
            RecordData::HINFO { ref cpu, ref os } => {
                let mut buffer = Vec::with_capacity(2 + cpu.len() + os.len());
                buffer.push(cpu.len() as u8);
                buffer.extend_from_slice(&cpu);
                buffer.push(os.len() as u8);
                buffer.extend_from_slice(&os);
                buffer
            }
            RecordData::MINFO { ref rmailbx, ref emailbx } => {
                let mut buffer = Vec::with_capacity(rmailbx.byte_size() + emailbx.byte_size());
                buffer.extend_from_slice(&rmailbx.to_bytes());
                buffer.extend_from_slice(&emailbx.to_bytes());
                buffer
            }
            RecordData::MX { ref preference, ref exchange } => {
                let mut buffer = Vec::with_capacity(exchange.byte_size() + 2);
                buffer.extend_from_slice(&u16::to_be_bytes(*preference));
                buffer.extend_from_slice(&exchange.to_bytes());
                buffer
            },
            RecordData::TXT(ref store) => store.iter().fold(Vec::new(), |mut buff, elem| {
                let txt_bin = elem.as_bytes();
                buff.push(txt_bin.len() as u8);
                buff.extend_from_slice(txt_bin);
                buff
            }),
            RecordData::AAAA(ref buffer) => buffer.octets().to_vec(),
            RecordData::SRV { ref priority, ref weight, ref port, ref target } => {
                let mut buff = Vec::with_capacity(6 + target.byte_size());
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(&u16::to_be_bytes(*port));
                buff.extend_from_slice(&target.to_bytes());
                buff
            },
        }
    }

    fn to_bytes_compressed(&self, names: &mut std::collections::HashMap<u64, usize>, outer_off: usize) -> Vec<u8> {
        match self {
            RecordData::A(ref buffer) => buffer.octets().to_vec(),
            RecordData::NS(ref name) => name.to_bytes_compressed(names, outer_off),
            RecordData::CNAME(ref name) => name.to_bytes_compressed(names, outer_off),
            RecordData::SOA { ref mname, ref rname, ref serial, ref refresh, ref retry, ref expire, ref minimum  } => {
                let mut buffer = Vec::with_capacity(mname.byte_size() + rname.byte_size() + 64);
                buffer.extend_from_slice(&mname.to_bytes_compressed(names, outer_off));
                buffer.extend_from_slice(&rname.to_bytes_compressed(names, outer_off + buffer.len()));
                buffer.extend_from_slice(&u32::to_be_bytes(*serial));
                buffer.extend_from_slice(&u32::to_be_bytes(*refresh));
                buffer.extend_from_slice(&u32::to_be_bytes(*retry));
                buffer.extend_from_slice(&u32::to_be_bytes(*expire));
                buffer.extend_from_slice(&u32::to_be_bytes(*minimum));
                buffer
            },
            RecordData::NULL(ref buffer) => buffer.clone(),
            RecordData::WKS { ref address, ref protocol, ref bitmap } => {
                let mut buffer = Vec::with_capacity(4 + 1 + bitmap.len());
                buffer.extend_from_slice(&u32::to_be_bytes(*address));
                buffer.extend_from_slice(&u8::to_be_bytes(*protocol));
                buffer.extend_from_slice(&bitmap);
                buffer
            },
            RecordData::PTR(ref name) => name.to_bytes_compressed(names, outer_off),
            RecordData::HINFO { ref cpu, ref os } => {
                let mut buffer = Vec::with_capacity(2 + cpu.len() + os.len());
                buffer.push(cpu.len() as u8);
                buffer.extend_from_slice(&cpu);
                buffer.push(os.len() as u8);
                buffer.extend_from_slice(&os);
                buffer
            }
            RecordData::MINFO { ref rmailbx, ref emailbx } => {
                let mut buffer = Vec::with_capacity(rmailbx.byte_size() + emailbx.byte_size());
                buffer.extend_from_slice(&rmailbx.to_bytes_compressed(names, outer_off));
                buffer.extend_from_slice(&emailbx.to_bytes_compressed(names, outer_off + buffer.len()));
                buffer
            }
            RecordData::MX { ref preference, ref exchange } => {
                let mut buffer = Vec::with_capacity(exchange.byte_size() + 2);
                buffer.extend_from_slice(&u16::to_be_bytes(*preference));
                buffer.extend_from_slice(&exchange.to_bytes_compressed(names, outer_off));
                buffer
            },
            RecordData::TXT(ref store) => store.iter().fold(Vec::new(), |mut buff, elem| {
                let txt_bin = elem.as_bytes();
                buff.push(txt_bin.len() as u8);
                buff.extend_from_slice(txt_bin);
                buff
            }),
            RecordData::AAAA(ref buffer) => buffer.octets().to_vec(),
            RecordData::SRV { ref priority, ref weight, ref port, ref target } => {
                let mut buff = Vec::with_capacity(6 + target.byte_size());
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(&u16::to_be_bytes(*port));
                buff.extend_from_slice(&target.to_bytes_compressed(names, outer_off));
                buff
            },
        }
    }
}


#[derive(Clone, Debug)]
pub struct ResourceRecord {
    pub a_name: FQDN,
    pub a_type: RecordType,
    pub a_class: RecordClass,
    pub time_to_live: u32,
    pub rdata: RecordData,
}

impl ResourceRecord {
    pub fn with(a_name: &str, a_type: RecordType, a_class: RecordClass, ttl: u32, rdata: RecordData) -> Self {
        ResourceRecord { a_name: FQDN::with(a_name), a_type, a_class, time_to_live: ttl, rdata }
    }

    pub fn get_data_raw(&self) -> Vec<u8> {
        self.rdata.to_bytes()
    }
}

impl ByteConvertible for ResourceRecord {
    fn byte_size(&self) -> usize {
            self.a_name.byte_size() +
            size_of::<u16>() +
            size_of::<u16>() +
            size_of::<u32>() +
            self.rdata.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        buffer.extend_from_slice(&self.a_name.to_bytes());
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class as u16));
        buffer.extend_from_slice(&u32::to_be_bytes(self.time_to_live));
        buffer.extend_from_slice(&u16::to_be_bytes(self.rdata.byte_size() as u16));
        buffer.extend_from_slice(&self.rdata.to_bytes());
        buffer
    }

    fn to_bytes_compressed(&self, names: &mut std::collections::HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.a_name.to_bytes_compressed(names, offset));
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class as u16));
        buffer.extend_from_slice(&u32::to_be_bytes(self.time_to_live));

        let compressed_rdata = self.rdata.to_bytes_compressed(names, offset + buffer.len() + 2);

        buffer.extend_from_slice(&u16::to_be_bytes(compressed_rdata.len() as u16));
        buffer.extend_from_slice(&compressed_rdata);

        buffer
    }
}
