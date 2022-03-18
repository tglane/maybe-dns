use std::mem::size_of;
use std::array::TryFromSliceError;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::util::ByteConvertible;
use super::error::DnsError;
use super::util::{to_fqdn, from_fqdn};

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
    NS(String),
    CNAME(String),
    SOA {
        mname: String,
        rname: String,
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
    PTR(String),
    HINFO {
        cpu: Vec<u8>,
        os: Vec<u8>,
    },
    MINFO {
        rmailbx: String,
        emailbx: String,
    },
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(Vec<String>),
    AAAA(Ipv6Addr),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

impl RecordData {
    pub fn from(rec_type: RecordType, buffer: &[u8]) -> Result<Self, DnsError> {
        Ok(match rec_type {
            RecordType::A => RecordData::A(Ipv4Addr::from(u32::from_be_bytes(buffer.try_into()?))),
            RecordType::NS => RecordData::NS(from_fqdn(buffer).0),
            RecordType::CNAME => RecordData::CNAME(from_fqdn(buffer).0),
            RecordType::SOA => RecordData::parse_soa(buffer)?,
            RecordType::NULL => RecordData::NULL(buffer.to_vec()),
            RecordType::WKS => RecordData::parse_wks(buffer)?,
            RecordType::PTR => RecordData::PTR(from_fqdn(buffer).0),
            RecordType::HINFO => RecordData::parse_hinfo(buffer)?,
            RecordType::MINFO => RecordData::parse_minfo(buffer)?,
            RecordType::MX => RecordData::parse_mx(buffer)?,
            RecordType::TXT => RecordData::parse_txt(buffer),
            RecordType::AAAA => RecordData::AAAA(Ipv6Addr::from(u128::from_be_bytes(buffer.try_into()?))),
            RecordType::SRV => RecordData::parse_srv(buffer)?,
        })
    }

    fn parse_soa(buffer: &[u8]) -> Result<Self, TryFromSliceError> {
        let (mname, idx_advanced) = from_fqdn(buffer);
        let (rname, idx_advanced) = from_fqdn(&buffer[idx_advanced..]);
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
        let (rmailbx, idx_advanced) = from_fqdn(buffer);
        let (emailbx, _) = from_fqdn(&buffer[idx_advanced..]);

        Ok(RecordData::MINFO { rmailbx, emailbx })
    }

    fn parse_mx(buffer: &[u8]) -> Result<Self, TryFromSliceError> {
        let preference = u16::from_be_bytes(buffer[0..2].try_into()?);
        let exchange = from_fqdn(&buffer[2..]).0;

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
        let target = from_fqdn(&buffer[6..buffer.len()]).0;

        Ok(RecordData::SRV { priority, weight, port, target })
    }
}

impl ByteConvertible for RecordData {
    fn byte_size(&self) -> usize {
        match self {
            RecordData::A(_) => 4,
            RecordData::NS(ref name) => name.len() + 2,
            RecordData::CNAME(ref name) => name.len() + 2,
            RecordData::SOA { ref mname, ref rname, serial: _, refresh: _, retry: _, expire: _, minimum: _ } => {
                mname.len() + 2 + rname.len() + 2 + 4 + 4 + 4 + 4 + 4
            },
            RecordData::NULL(ref buffer) => buffer.len(),
            RecordData::WKS { address: _, protocol: _, ref bitmap } => 4 + 1 + bitmap.len(),
            RecordData::PTR(ref name) => name.len() + 2,
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
            RecordData::NS(ref name) => to_fqdn(&name),
            RecordData::CNAME(ref name) => to_fqdn(&name),
            RecordData::SOA { ref mname, ref rname, ref serial, ref refresh, ref retry, ref expire, ref minimum  } => {
                let mut buffer = to_fqdn(&mname);
                buffer.extend_from_slice(&to_fqdn(&rname));
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
            RecordData::PTR(ref name) => to_fqdn(name),
            RecordData::HINFO { ref cpu, ref os } => {
                let mut buffer = Vec::with_capacity(2 + cpu.len() + os.len());
                buffer.push(cpu.len() as u8);
                buffer.extend_from_slice(&cpu);
                buffer.push(os.len() as u8);
                buffer.extend_from_slice(&os);
                buffer
            }
            RecordData::MINFO { ref rmailbx, ref emailbx } => {
                let mut buffer = Vec::with_capacity(rmailbx.len() + 2 + emailbx.len() + 2);
                buffer.extend_from_slice(&to_fqdn(&rmailbx));
                buffer.extend_from_slice(&to_fqdn(&emailbx));
                buffer
            }
            RecordData::MX { ref preference, ref exchange } => {
                let mut buffer = Vec::with_capacity(2 + exchange.len() + 2);
                buffer.extend_from_slice(&u16::to_be_bytes(*preference));
                buffer.extend_from_slice(&to_fqdn(&exchange));
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
                let mut buff = Vec::new();
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(&u16::to_be_bytes(*port));
                buff.extend_from_slice(&to_fqdn(&target));
                buff
            },
        }
    }
}


#[derive(Clone, Debug)]
pub struct ResourceRecord {
    pub a_name: Vec<u8>,
    pub a_type: RecordType,
    pub a_class: RecordClass,
    pub time_to_live: u32,
    pub rdata: RecordData
}

impl ResourceRecord {
    pub fn with(a_name: &str, a_type: RecordType, a_class: RecordClass, ttl: u32, rdata: RecordData) -> Self {
        ResourceRecord { a_name: a_name.as_bytes().to_vec(), a_type, a_class, time_to_live: ttl, rdata }
    }

    pub fn get_name_as_string(&self) -> String {
        from_fqdn(&self.a_name).0
    }

    pub fn set_name_from_string(&mut self, hostname: &str) {
        self.a_name = to_fqdn(hostname);
    }

    pub fn get_data_raw(&self) -> Vec<u8> {
        self.rdata.to_bytes()
    }
}

impl ByteConvertible for ResourceRecord {
    fn byte_size(&self) -> usize {
            self.a_name.len() +
            size_of::<u16>() +
            size_of::<u16>() +
            size_of::<u32>() +
            self.rdata.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.a_name);
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class as u16));
        buffer.extend_from_slice(&u32::to_be_bytes(self.time_to_live));
        buffer.extend_from_slice(&u16::to_be_bytes(self.rdata.byte_size() as u16));
        buffer.extend_from_slice(&self.rdata.to_bytes());
        buffer
    }
}
