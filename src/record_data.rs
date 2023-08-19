use std::convert::{From, TryFrom, TryInto};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::resource::RecordType;

#[derive(Clone, Debug, PartialEq, Eq)]
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
        bitmap: Vec<u8>,
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
    NSEC {
        next_domain_name: FQDN,
        type_mask: Vec<u8>,
    },
}

impl RecordData {
    pub fn from(rec_type: RecordType, buffer: &mut DnsBuffer) -> Result<Self, DnsError> {
        Ok(match rec_type {
            RecordType::A => RecordData::A(Ipv4Addr::from(buffer.extract_u32()?)),
            RecordType::NS => RecordData::NS(buffer.extract_fqdn()?),
            RecordType::CNAME => RecordData::CNAME(buffer.extract_fqdn()?),
            RecordType::SOA => RecordData::SOA {
                mname: FQDN::try_from(buffer as &mut _)?,
                rname: FQDN::try_from(buffer as &mut _)?,
                serial: buffer.extract_u32()?,
                refresh: buffer.extract_u32()?,
                retry: buffer.extract_u32()?,
                expire: buffer.extract_u32()?,
                minimum: buffer.extract_u32()?,
            },
            RecordType::NULL => RecordData::NULL(buffer.read_bytes(buffer.remaining())?.to_vec()),
            RecordType::WKS => {
                let address = buffer.extract_u32()?;
                let protocol = buffer.extract_u8()?;
                let bitmap = buffer.read_bytes(buffer.remaining())?.to_vec();
                RecordData::WKS {
                    address,
                    protocol,
                    bitmap,
                }
            }
            RecordType::PTR => RecordData::PTR(FQDN::try_from(buffer)?),
            RecordType::HINFO => {
                let cpu_len = buffer.extract_u8()? as usize;
                let cpu = buffer.extract_bytes(cpu_len)?.to_vec();
                let os_len = buffer.extract_u8()? as usize;
                let os = buffer.extract_bytes(os_len)?.to_vec();
                RecordData::HINFO { cpu, os }
            }
            RecordType::MINFO => RecordData::MINFO {
                rmailbx: buffer.extract_fqdn()?,
                emailbx: buffer.extract_fqdn()?,
            },
            RecordType::MX => {
                let preference = buffer.extract_u16()?;
                let exchange = buffer.extract_fqdn()?;
                RecordData::MX {
                    preference,
                    exchange,
                }
            }
            RecordType::TXT => {
                let mut txt_store = Vec::<String>::new();
                while buffer.remaining() > 0 {
                    let txt_size = buffer.extract_u8()?;
                    txt_store.push(
                        String::from_utf8_lossy(buffer.extract_bytes(txt_size as usize)?)
                            .to_string(),
                    );
                }
                RecordData::TXT(txt_store)
            }
            RecordType::AAAA => RecordData::AAAA(Ipv6Addr::from(u128::from_be_bytes(
                buffer.read_bytes(16)?.try_into()?,
            ))),
            RecordType::SRV => {
                let priority = buffer.extract_u16()?;
                let weight = buffer.extract_u16()?;
                let port = buffer.extract_u16()?;
                let target = buffer.extract_fqdn()?;
                RecordData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            RecordType::NSEC => {
                let next_domain_name = buffer.extract_fqdn()?;
                let type_mask = buffer.read_bytes(buffer.remaining())?.to_vec();
                RecordData::NSEC {
                    next_domain_name,
                    type_mask,
                }
            }
        })
    }
}

impl ByteConvertible for RecordData {
    fn byte_size(&self) -> usize {
        match self {
            RecordData::A(_) => 4,
            RecordData::NS(ref name) => name.byte_size(),
            RecordData::CNAME(ref name) => name.byte_size(),
            RecordData::SOA {
                ref mname,
                ref rname,
                serial: _,
                refresh: _,
                retry: _,
                expire: _,
                minimum: _,
            } => mname.len() + 2 + rname.len() + 2 + 4 + 4 + 4 + 4 + 4,
            RecordData::NULL(ref buffer) => buffer.len(),
            RecordData::WKS {
                address: _,
                protocol: _,
                ref bitmap,
            } => 4 + 1 + bitmap.len(),
            RecordData::PTR(ref name) => name.byte_size(),
            RecordData::HINFO { ref cpu, ref os } => 2 + cpu.len() + os.len(),
            RecordData::MINFO {
                ref rmailbx,
                ref emailbx,
            } => rmailbx.len() + 2 + emailbx.len() + 2,
            RecordData::MX {
                preference: _,
                ref exchange,
            } => 2 + exchange.len() + 2,
            RecordData::TXT(ref store) => store.iter().fold(0, |acc, elem| acc + elem.len() + 1),
            RecordData::AAAA(_) => 16,
            RecordData::SRV {
                priority: _,
                weight: _,
                port: _,
                ref target,
            } => 2 + 2 + 2 + target.len() + 2,
            RecordData::NSEC {
                ref next_domain_name,
                ref type_mask,
            } => next_domain_name.byte_size() + type_mask.len(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            RecordData::A(ref buffer) => buffer.octets().to_vec(),
            RecordData::NS(ref name) => name.to_bytes(),
            RecordData::CNAME(ref name) => name.to_bytes(),
            RecordData::SOA {
                ref mname,
                ref rname,
                ref serial,
                ref refresh,
                ref retry,
                ref expire,
                ref minimum,
            } => {
                let mut buffer = Vec::with_capacity(mname.byte_size() + rname.byte_size() + 64);
                buffer.extend_from_slice(&mname.to_bytes());
                buffer.extend_from_slice(&rname.to_bytes());
                buffer.extend_from_slice(&u32::to_be_bytes(*serial));
                buffer.extend_from_slice(&u32::to_be_bytes(*refresh));
                buffer.extend_from_slice(&u32::to_be_bytes(*retry));
                buffer.extend_from_slice(&u32::to_be_bytes(*expire));
                buffer.extend_from_slice(&u32::to_be_bytes(*minimum));
                buffer
            }
            RecordData::NULL(ref buffer) => buffer.clone(),
            RecordData::WKS {
                ref address,
                ref protocol,
                ref bitmap,
            } => {
                let mut buffer = Vec::with_capacity(4 + 1 + bitmap.len());
                buffer.extend_from_slice(&u32::to_be_bytes(*address));
                buffer.extend_from_slice(&u8::to_be_bytes(*protocol));
                buffer.extend_from_slice(&bitmap);
                buffer
            }
            RecordData::PTR(ref name) => name.to_bytes(),
            RecordData::HINFO { ref cpu, ref os } => {
                let mut buffer = Vec::with_capacity(2 + cpu.len() + os.len());
                buffer.push(cpu.len() as u8);
                buffer.extend_from_slice(&cpu);
                buffer.push(os.len() as u8);
                buffer.extend_from_slice(&os);
                buffer
            }
            RecordData::MINFO {
                ref rmailbx,
                ref emailbx,
            } => {
                let mut buffer = Vec::with_capacity(rmailbx.byte_size() + emailbx.byte_size());
                buffer.extend_from_slice(&rmailbx.to_bytes());
                buffer.extend_from_slice(&emailbx.to_bytes());
                buffer
            }
            RecordData::MX {
                ref preference,
                ref exchange,
            } => {
                let mut buffer = Vec::with_capacity(exchange.byte_size() + 2);
                buffer.extend_from_slice(&u16::to_be_bytes(*preference));
                buffer.extend_from_slice(&exchange.to_bytes());
                buffer
            }
            RecordData::TXT(ref store) => store.iter().fold(Vec::new(), |mut buff, elem| {
                let txt_bin = elem.as_bytes();
                buff.push(txt_bin.len() as u8);
                buff.extend_from_slice(txt_bin);
                buff
            }),
            RecordData::AAAA(ref buffer) => buffer.octets().to_vec(),
            RecordData::SRV {
                ref priority,
                ref weight,
                ref port,
                ref target,
            } => {
                let mut buff = Vec::with_capacity(6 + target.byte_size());
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(&u16::to_be_bytes(*port));
                buff.extend_from_slice(&target.to_bytes());
                buff
            }
            RecordData::NSEC {
                ref next_domain_name,
                ref type_mask,
            } => {
                let mut buff = next_domain_name.to_bytes();
                buff.extend_from_slice(&type_mask);
                buff
            }
        }
    }
}

impl CompressedByteConvertible for RecordData {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        outer_off: usize,
    ) -> Vec<u8> {
        match self {
            RecordData::A(ref buffer) => buffer.octets().to_vec(),
            RecordData::NS(ref name) => name.to_bytes_compressed(names, outer_off),
            RecordData::CNAME(ref name) => name.to_bytes_compressed(names, outer_off),
            RecordData::SOA {
                ref mname,
                ref rname,
                ref serial,
                ref refresh,
                ref retry,
                ref expire,
                ref minimum,
            } => {
                let mut buffer = Vec::with_capacity(mname.byte_size() + rname.byte_size() + 64);
                buffer.extend_from_slice(&mname.to_bytes_compressed(names, outer_off));
                buffer
                    .extend_from_slice(&rname.to_bytes_compressed(names, outer_off + buffer.len()));
                buffer.extend_from_slice(&u32::to_be_bytes(*serial));
                buffer.extend_from_slice(&u32::to_be_bytes(*refresh));
                buffer.extend_from_slice(&u32::to_be_bytes(*retry));
                buffer.extend_from_slice(&u32::to_be_bytes(*expire));
                buffer.extend_from_slice(&u32::to_be_bytes(*minimum));
                buffer
            }
            RecordData::NULL(ref buffer) => buffer.clone(),
            RecordData::WKS {
                ref address,
                ref protocol,
                ref bitmap,
            } => {
                let mut buffer = Vec::with_capacity(4 + 1 + bitmap.len());
                buffer.extend_from_slice(&u32::to_be_bytes(*address));
                buffer.extend_from_slice(&u8::to_be_bytes(*protocol));
                buffer.extend_from_slice(&bitmap);
                buffer
            }
            RecordData::PTR(ref name) => name.to_bytes_compressed(names, outer_off),
            RecordData::HINFO { ref cpu, ref os } => {
                let mut buffer = Vec::with_capacity(2 + cpu.len() + os.len());
                buffer.push(cpu.len() as u8);
                buffer.extend_from_slice(&cpu);
                buffer.push(os.len() as u8);
                buffer.extend_from_slice(&os);
                buffer
            }
            RecordData::MINFO {
                ref rmailbx,
                ref emailbx,
            } => {
                let mut buffer = Vec::with_capacity(rmailbx.byte_size() + emailbx.byte_size());
                buffer.extend_from_slice(&rmailbx.to_bytes_compressed(names, outer_off));
                buffer.extend_from_slice(
                    &emailbx.to_bytes_compressed(names, outer_off + buffer.len()),
                );
                buffer
            }
            RecordData::MX {
                ref preference,
                ref exchange,
            } => {
                let mut buffer = Vec::with_capacity(exchange.byte_size() + 2);
                buffer.extend_from_slice(&u16::to_be_bytes(*preference));
                buffer.extend_from_slice(&exchange.to_bytes_compressed(names, outer_off + 2));
                buffer
            }
            RecordData::TXT(ref store) => store.iter().fold(Vec::new(), |mut buff, elem| {
                let txt_bin = elem.as_bytes();
                buff.push(txt_bin.len() as u8);
                buff.extend_from_slice(txt_bin);
                buff
            }),
            RecordData::AAAA(ref buffer) => buffer.octets().to_vec(),
            RecordData::SRV {
                ref priority,
                ref weight,
                ref port,
                ref target,
            } => {
                let mut buff = Vec::with_capacity(6 + target.byte_size());
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(&u16::to_be_bytes(*port));
                buff.extend_from_slice(&target.to_bytes_compressed(names, outer_off + 6));
                buff
            }
            RecordData::NSEC {
                ref next_domain_name,
                ref type_mask,
            } => {
                let mut buff = next_domain_name.to_bytes_compressed(names, outer_off);
                buff.extend_from_slice(&type_mask);
                buff
            }
        }
    }
}
