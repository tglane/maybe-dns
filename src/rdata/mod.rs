mod dnssec;

pub use self::dnssec::{DNSKEY, DS, NSEC, RRSIG};

use std::collections::HashMap;
use std::convert::{From, TryFrom, TryInto};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::resource::RecordType;

// #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    LOC {
        version: u8,
        size: u8,
        horiz_pre: u8,
        vert_pre: u8,
        latitude: u32,
        longitude: u32,
        altitude: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: FQDN,
    },
    NAPTR {
        order: u16,
        preference: u16,
        flags: Vec<u8>,
        services: Vec<u8>,
        regexp: Vec<u8>,
        replacement: FQDN,
    },
    OPT(HashMap<u16, Vec<u8>>),
    DS(DS),
    SSHFP {
        algorithm: SSHFPAlgorithm,
        fingerprint_type: SSHFPFingerprintType,
        fingerprint: Vec<u8>,
    },
    RRSIG(RRSIG),
    NSEC(NSEC),
    DNSKKEY(DNSKEY),
    TLSA {
        cert_usage: u8,
        selector: TLSASelector,
        matching_type: TLSAMatchingType,
        associated_data: Vec<u8>,
    },
    OPENPGPKEY(Vec<u8>),
    EUI48([u8; 6]),
    EUI64([u8; 8]),
    URI {
        priority: u16,
        weight: u16,
        target: Vec<u8>,
    },
    CAA {
        issuer_critical_flag: bool,
        tag: String,
        value: Vec<u8>,
    },
}

impl RecordData {
    pub fn from(rec_type: RecordType, buffer: &mut DnsBuffer) -> Result<Self, DnsError> {
        Ok(match rec_type {
            RecordType::A => Self::A(Ipv4Addr::from(buffer.extract_u32()?)),
            RecordType::NS => Self::NS(buffer.extract_fqdn()?),
            RecordType::CNAME => Self::CNAME(buffer.extract_fqdn()?),
            RecordType::SOA => Self::SOA {
                mname: FQDN::try_from(buffer as &mut _)?,
                rname: FQDN::try_from(buffer as &mut _)?,
                serial: buffer.extract_u32()?,
                refresh: buffer.extract_u32()?,
                retry: buffer.extract_u32()?,
                expire: buffer.extract_u32()?,
                minimum: buffer.extract_u32()?,
            },
            RecordType::NULL => Self::NULL(buffer.extract_bytes(buffer.remaining())?.to_vec()),
            RecordType::WKS => {
                let address = buffer.extract_u32()?;
                let protocol = buffer.extract_u8()?;
                let bitmap = buffer.extract_bytes(buffer.remaining())?.to_vec();
                Self::WKS {
                    address,
                    protocol,
                    bitmap,
                }
            }
            RecordType::PTR => Self::PTR(FQDN::try_from(buffer)?),
            RecordType::HINFO => Self::HINFO {
                cpu: buffer.extract_character_string()?,
                os: buffer.extract_character_string()?,
            },
            RecordType::MINFO => Self::MINFO {
                rmailbx: buffer.extract_fqdn()?,
                emailbx: buffer.extract_fqdn()?,
            },
            RecordType::MX => {
                let preference = buffer.extract_u16()?;
                let exchange = buffer.extract_fqdn()?;
                Self::MX {
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
                Self::TXT(txt_store)
            }
            RecordType::AAAA => Self::AAAA(Ipv6Addr::from(u128::from_be_bytes(
                buffer.extract_bytes(16)?.try_into()?,
            ))),
            RecordType::LOC => Self::LOC {
                version: buffer.extract_u8()?,
                size: buffer.extract_u8()?,
                horiz_pre: buffer.extract_u8()?,
                vert_pre: buffer.extract_u8()?,
                latitude: buffer.extract_u32()?,
                longitude: buffer.extract_u32()?,
                altitude: buffer.extract_u32()?,
            },
            RecordType::SRV => {
                let priority = buffer.extract_u16()?;
                let weight = buffer.extract_u16()?;
                let port = buffer.extract_u16()?;
                let target = buffer.extract_fqdn()?;
                Self::SRV {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            RecordType::NAPTR => Self::NAPTR {
                order: buffer.extract_u16()?,
                preference: buffer.extract_u16()?,
                flags: buffer.extract_character_string()?,
                services: buffer.extract_character_string()?,
                regexp: buffer.extract_character_string()?,
                replacement: buffer.extract_fqdn()?,
            },
            RecordType::OPT => {
                let mut kv_data = HashMap::new();
                while buffer.remaining() > 0 {
                    let opt_code = buffer.extract_u16()?;
                    let opt_data_len = buffer.extract_u16()?;
                    let opt_data = buffer.extract_bytes(opt_data_len as usize)?;

                    kv_data.insert(opt_code, opt_data.to_vec());
                }
                Self::OPT(kv_data)
            }
            RecordType::DS => Self::DS(DS::try_from(buffer)?),
            RecordType::SSHFP => Self::SSHFP {
                algorithm: buffer.extract_u8()?.try_into()?,
                fingerprint_type: buffer.extract_u8()?.try_into()?,
                fingerprint: buffer.extract_bytes(buffer.remaining())?.to_vec(),
            },
            RecordType::RRSIG => Self::RRSIG(RRSIG::try_from(buffer)?),
            RecordType::NSEC => Self::NSEC(NSEC::try_from(buffer)?),
            RecordType::DNSKEY => Self::DNSKKEY(DNSKEY::try_from(buffer)?),
            RecordType::TLSA => Self::TLSA {
                cert_usage: buffer.extract_u8()?,
                selector: buffer.extract_u8()?.try_into()?,
                matching_type: buffer.extract_u8()?.try_into()?,
                associated_data: buffer.extract_bytes(buffer.remaining())?.to_vec(),
            },
            RecordType::OPENPGPKEY => {
                Self::OPENPGPKEY(buffer.extract_bytes(buffer.remaining())?.to_vec())
            }
            RecordType::EUI48 => Self::EUI48(buffer.extract_bytes(6)?.try_into()?),
            RecordType::EUI64 => Self::EUI64(buffer.extract_bytes(8)?.try_into()?),
            RecordType::URI => Self::URI {
                priority: buffer.extract_u16()?,
                weight: buffer.extract_u16()?,
                target: buffer.extract_bytes(buffer.remaining())?.to_vec(),
            },
            RecordType::CAA => {
                let flags = buffer.extract_u8()?;
                let tag_len = buffer.extract_u8()?;

                if tag_len == 0 {
                    return Err(DnsError::InvalidPacketData);
                }

                let tag =
                    String::from_utf8_lossy(buffer.extract_bytes(tag_len as usize)?).to_string();
                let value = buffer.extract_bytes(buffer.remaining())?.to_vec();

                Self::CAA {
                    issuer_critical_flag: (flags & 0b10000000) != 0,
                    tag,
                    value,
                }
            }
        })
    }
}

impl ByteConvertible for RecordData {
    fn byte_size(&self) -> usize {
        match self {
            Self::A(_) => 4,
            Self::NS(ref name) => name.byte_size(),
            Self::CNAME(ref name) => name.byte_size(),
            Self::SOA {
                ref mname,
                ref rname,
                serial: _,
                refresh: _,
                retry: _,
                expire: _,
                minimum: _,
            } => mname.len() + 2 + rname.len() + 2 + 4 + 4 + 4 + 4 + 4,
            Self::NULL(ref buffer) => buffer.len(),
            Self::WKS {
                address: _,
                protocol: _,
                ref bitmap,
            } => 4 + 1 + bitmap.len(),
            Self::PTR(ref name) => name.byte_size(),
            Self::HINFO { ref cpu, ref os } => 2 + cpu.len() + os.len(),
            Self::MINFO {
                ref rmailbx,
                ref emailbx,
            } => rmailbx.len() + 2 + emailbx.len() + 2,
            Self::MX {
                preference: _,
                ref exchange,
            } => 2 + exchange.len() + 2,
            Self::TXT(ref store) => store.iter().fold(0, |acc, elem| acc + elem.len() + 1),
            Self::AAAA(_) => 16,
            Self::LOC {
                version: _,
                size: _,
                horiz_pre: _,
                vert_pre: _,
                latitude: _,
                longitude: _,
                altitude: _,
            } => 16,
            Self::SRV {
                priority: _,
                weight: _,
                port: _,
                ref target,
            } => 2 + 2 + 2 + target.len() + 2,
            Self::NAPTR {
                order: _,
                preference: _,
                ref flags,
                ref services,
                ref regexp,
                ref replacement,
            } => {
                2 + 2 + flags.len() + 1 + services.len() + 1 + regexp.len() + 1 + replacement.len()
            }
            Self::OPT(kv_data) => 2 + 2 + kv_data.iter().fold(0, |acc, elem| acc + elem.1.len()),
            Self::DS(ds) => ds.byte_size(),
            Self::SSHFP {
                algorithm: _,
                fingerprint_type: _,
                ref fingerprint,
            } => 1 + 1 + fingerprint.len(),
            Self::RRSIG(rrsig) => rrsig.byte_size(),
            Self::NSEC(nsec) => nsec.byte_size(),
            Self::DNSKKEY(dnskey) => dnskey.byte_size(),
            Self::TLSA {
                cert_usage: _,
                selector: _,
                matching_type: _,
                ref associated_data,
            } => 3 + associated_data.len(),
            Self::OPENPGPKEY(data) => data.len(),
            Self::EUI48(_) => 6,
            Self::EUI64(_) => 8,
            Self::URI {
                priority: _,
                weight: _,
                ref target,
            } => 2 + 2 + target.len(),
            Self::CAA {
                issuer_critical_flag: _,
                ref tag,
                ref value,
            } => 2 + tag.len() + value.len(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::A(ref buffer) => buffer.octets().to_vec(),
            Self::NS(ref name) => name.to_bytes(),
            Self::CNAME(ref name) => name.to_bytes(),
            Self::SOA {
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
            Self::NULL(ref buffer) => buffer.clone(),
            Self::WKS {
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
            Self::PTR(ref name) => name.to_bytes(),
            Self::HINFO { ref cpu, ref os } => {
                let mut buffer = Vec::with_capacity(2 + cpu.len() + os.len());
                buffer.push(cpu.len() as u8);
                buffer.extend_from_slice(&cpu);
                buffer.push(os.len() as u8);
                buffer.extend_from_slice(&os);
                buffer
            }
            Self::MINFO {
                ref rmailbx,
                ref emailbx,
            } => {
                let mut buffer = Vec::with_capacity(rmailbx.byte_size() + emailbx.byte_size());
                buffer.extend_from_slice(&rmailbx.to_bytes());
                buffer.extend_from_slice(&emailbx.to_bytes());
                buffer
            }
            Self::MX {
                ref preference,
                ref exchange,
            } => {
                let mut buffer = Vec::with_capacity(exchange.byte_size() + 2);
                buffer.extend_from_slice(&u16::to_be_bytes(*preference));
                buffer.extend_from_slice(&exchange.to_bytes());
                buffer
            }
            Self::TXT(ref store) => store.iter().fold(Vec::new(), |mut buff, elem| {
                let txt_bin = elem.as_bytes();
                buff.push(txt_bin.len() as u8);
                buff.extend_from_slice(txt_bin);
                buff
            }),
            Self::AAAA(ref buffer) => buffer.octets().to_vec(),
            Self::LOC {
                ref version,
                ref size,
                ref horiz_pre,
                ref vert_pre,
                ref latitude,
                ref longitude,
                ref altitude,
            } => {
                let mut buffer = Vec::with_capacity(16);
                buffer.push(*version);
                buffer.push(*size);
                buffer.push(*horiz_pre);
                buffer.push(*vert_pre);
                buffer.extend_from_slice(&u32::to_be_bytes(*latitude));
                buffer.extend_from_slice(&u32::to_be_bytes(*longitude));
                buffer.extend_from_slice(&u32::to_be_bytes(*altitude));
                buffer
            }
            Self::SRV {
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
            Self::NAPTR {
                order,
                preference,
                ref flags,
                ref services,
                ref regexp,
                ref replacement,
            } => {
                let mut buff = Vec::with_capacity(self.byte_size());
                buff.extend_from_slice(&u16::to_be_bytes(*order));
                buff.extend_from_slice(&u16::to_be_bytes(*preference));
                buff.push(flags.len() as u8);
                buff.extend_from_slice(&flags);
                buff.push(services.len() as u8);
                buff.extend_from_slice(&services);
                buff.push(regexp.len() as u8);
                buff.extend_from_slice(&regexp);
                buff.extend_from_slice(&replacement.to_bytes());
                buff
            }
            Self::OPT(kv_data) => {
                let mut buff = Vec::with_capacity(self.byte_size());
                for (code, data) in kv_data.iter() {
                    buff.extend_from_slice(&u16::to_be_bytes(*code));
                    buff.extend_from_slice(&u16::to_be_bytes(data.len() as u16));
                    buff.extend_from_slice(&data);
                }
                buff
            }
            Self::DS(ds) => ds.to_bytes(),
            Self::SSHFP {
                algorithm,
                fingerprint_type,
                ref fingerprint,
            } => {
                let mut buff = Vec::<u8>::with_capacity(2 + fingerprint.len());
                buff.push((*algorithm).into());
                buff.push((*fingerprint_type).into());
                buff.extend_from_slice(fingerprint);
                buff
            }
            Self::RRSIG(rrsig) => rrsig.to_bytes(),
            Self::NSEC(nsec) => nsec.to_bytes(),
            Self::DNSKKEY(dnskey) => dnskey.to_bytes(),
            Self::TLSA {
                cert_usage,
                selector,
                matching_type,
                ref associated_data,
            } => {
                let mut buff = Vec::with_capacity(3 + associated_data.len());
                buff.push((*cert_usage).into());
                buff.push((*selector).into());
                buff.push((*matching_type).into());
                buff.extend_from_slice(associated_data);
                buff
            }
            Self::OPENPGPKEY(data) => data.clone(),
            Self::EUI48(octets) => octets.to_vec(),
            Self::EUI64(octets) => octets.to_vec(),
            Self::URI {
                priority,
                weight,
                ref target,
            } => {
                let mut buff = Vec::with_capacity(2 + 2 + target.len());
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(target);
                buff
            }
            Self::CAA {
                issuer_critical_flag,
                ref tag,
                ref value,
            } => {
                let mut buff = Vec::with_capacity(2 + tag.len() + value.len());
                buff.push((*issuer_critical_flag as u8) << 7);
                buff.push(tag.len() as u8);
                buff.extend_from_slice(tag.as_bytes());
                buff.extend_from_slice(&value);
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
            Self::A(ref buffer) => buffer.octets().to_vec(),
            Self::NS(ref name) => name.to_bytes_compressed(names, outer_off),
            Self::CNAME(ref name) => name.to_bytes_compressed(names, outer_off),
            Self::SOA {
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
            Self::NULL(ref buffer) => buffer.clone(),
            Self::WKS {
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
            Self::PTR(ref name) => name.to_bytes_compressed(names, outer_off),
            Self::HINFO { ref cpu, ref os } => {
                let mut buffer = Vec::with_capacity(2 + cpu.len() + os.len());
                buffer.push(cpu.len() as u8);
                buffer.extend_from_slice(&cpu);
                buffer.push(os.len() as u8);
                buffer.extend_from_slice(&os);
                buffer
            }
            Self::MINFO {
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
            Self::MX {
                ref preference,
                ref exchange,
            } => {
                let mut buffer = Vec::with_capacity(exchange.byte_size() + 2);
                buffer.extend_from_slice(&u16::to_be_bytes(*preference));
                buffer.extend_from_slice(&exchange.to_bytes_compressed(names, outer_off + 2));
                buffer
            }
            Self::TXT(ref store) => store.iter().fold(Vec::new(), |mut buff, elem| {
                let txt_bin = elem.as_bytes();
                buff.push(txt_bin.len() as u8);
                buff.extend_from_slice(txt_bin);
                buff
            }),
            Self::AAAA(ref buffer) => buffer.octets().to_vec(),
            Self::LOC {
                ref version,
                ref size,
                ref horiz_pre,
                ref vert_pre,
                ref latitude,
                ref longitude,
                ref altitude,
            } => {
                let mut buffer = Vec::with_capacity(16);
                buffer.push(*version);
                buffer.push(*size);
                buffer.push(*horiz_pre);
                buffer.push(*vert_pre);
                buffer.extend_from_slice(&u32::to_be_bytes(*latitude));
                buffer.extend_from_slice(&u32::to_be_bytes(*longitude));
                buffer.extend_from_slice(&u32::to_be_bytes(*altitude));
                buffer
            }
            Self::SRV {
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
            Self::NAPTR {
                order,
                preference,
                ref flags,
                ref services,
                ref regexp,
                ref replacement,
            } => {
                let mut buff = Vec::with_capacity(self.byte_size());
                buff.extend_from_slice(&u16::to_be_bytes(*order));
                buff.extend_from_slice(&u16::to_be_bytes(*preference));
                buff.push(flags.len() as u8);
                buff.extend_from_slice(&flags);
                buff.push(services.len() as u8);
                buff.extend_from_slice(&services);
                buff.push(regexp.len() as u8);
                buff.extend_from_slice(&regexp);
                buff.extend_from_slice(
                    &replacement.to_bytes_compressed(names, outer_off + buff.len()),
                );
                buff
            }
            Self::OPT(kv_data) => {
                let mut buff = Vec::with_capacity(0);
                for (code, data) in kv_data.iter() {
                    buff.extend_from_slice(&u16::to_be_bytes(*code));
                    buff.extend_from_slice(&u16::to_be_bytes(data.len() as u16));
                    buff.extend_from_slice(&data);
                }
                buff
            }
            Self::DS(ds) => ds.to_bytes(),
            Self::SSHFP {
                algorithm,
                fingerprint_type,
                ref fingerprint,
            } => {
                let mut buff = Vec::<u8>::with_capacity(2 + fingerprint.len());
                buff.push((*algorithm).into());
                buff.push((*fingerprint_type).into());
                buff.extend_from_slice(fingerprint);
                buff
            }
            Self::RRSIG(rrsig) => rrsig.to_bytes(),
            Self::NSEC(nsec) => nsec.to_bytes_compressed(names, outer_off),
            Self::DNSKKEY(dnskey) => dnskey.to_bytes(),
            Self::TLSA {
                cert_usage,
                selector,
                matching_type,
                ref associated_data,
            } => {
                let mut buff = Vec::with_capacity(3 + associated_data.len());
                buff.push((*cert_usage).into());
                buff.push((*selector).into());
                buff.push((*matching_type).into());
                buff.extend_from_slice(associated_data);
                buff
            }
            Self::OPENPGPKEY(data) => data.clone(),
            Self::EUI48(octets) => octets.to_vec(),
            Self::EUI64(octets) => octets.to_vec(),
            Self::URI {
                priority,
                weight,
                ref target,
            } => {
                let mut buff = Vec::with_capacity(2 + 2 + target.len());
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(target);
                buff
            }
            Self::CAA {
                issuer_critical_flag,
                ref tag,
                ref value,
            } => {
                let mut buff = Vec::with_capacity(2 + tag.len() + value.len());
                buff.push((*issuer_critical_flag as u8) << 7);
                buff.push(tag.len() as u8);
                buff.extend_from_slice(tag.as_bytes());
                buff.extend_from_slice(&value);
                buff
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SSHFPAlgorithm {
    Reserved = 0,
    RSA = 1,
    DSS = 2,
}

impl TryFrom<u8> for SSHFPAlgorithm {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::RSA),
            2 => Ok(Self::DSS),
            _ => Err(DnsError::InvalidSSHFPAlgorithm(value)),
        }
    }
}

impl From<SSHFPAlgorithm> for u8 {
    fn from(algorithm: SSHFPAlgorithm) -> Self {
        match algorithm {
            SSHFPAlgorithm::Reserved => 0,
            SSHFPAlgorithm::RSA => 1,
            SSHFPAlgorithm::DSS => 2,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SSHFPFingerprintType {
    Reserved = 0,
    SHA1 = 1,
}

impl TryFrom<u8> for SSHFPFingerprintType {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::SHA1),
            _ => Err(DnsError::InvalidSSHFPFingerprintType(value)),
        }
    }
}

impl From<SSHFPFingerprintType> for u8 {
    fn from(fingerprint_type: SSHFPFingerprintType) -> Self {
        match fingerprint_type {
            SSHFPFingerprintType::Reserved => 0,
            SSHFPFingerprintType::SHA1 => 1,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TLSASelector {
    Full = 0,
    SubjectPublicKeyInfo = 1,
}

impl TryFrom<u8> for TLSASelector {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::SubjectPublicKeyInfo),
            _ => Err(DnsError::InvalidSSHFPAlgorithm(value)),
        }
    }
}

impl From<TLSASelector> for u8 {
    fn from(selector: TLSASelector) -> Self {
        match selector {
            TLSASelector::Full => 0,
            TLSASelector::SubjectPublicKeyInfo => 1,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TLSAMatchingType {
    ExactMatch = 0,
    SHA256 = 1,
    SHA512 = 2,
}

impl TryFrom<u8> for TLSAMatchingType {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ExactMatch),
            1 => Ok(Self::SHA256),
            2 => Ok(Self::SHA512),
            _ => Err(DnsError::InvalidSSHFPAlgorithm(value)),
        }
    }
}

impl From<TLSAMatchingType> for u8 {
    fn from(matching_type: TLSAMatchingType) -> Self {
        match matching_type {
            TLSAMatchingType::ExactMatch => 0,
            TLSAMatchingType::SHA256 => 1,
            TLSAMatchingType::SHA512 => 2,
        }
    }
}
