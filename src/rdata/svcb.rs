use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// The SVCB ("Service Binding") and HTTPS resource records (RRs)
/// provide clients with complete instructions for access to a
/// service. This information enables improved performance and
/// privacy by avoiding transient connections to a suboptimal default
/// server, negotiating a preferred protocol, and providing relevant
/// public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Svcb {
    /// The priority of this record (relative to others, with
    /// lower values preferred). A value of 0 indicates AliasMode
    pub priority: u16,

    /// The domain name of either the alias target (for AliasMode)
    /// or the alternative endpoint (for ServiceMode).
    pub target_name: FQDN,

    /// A list of key=value pairs describing the alternative endpoint
    /// at TargetName (only used in ServiceMode and otherwise ignored).
    pub params: BTreeSet<Param>,
}

impl Svcb {
    /// The SVCB RR has two modes: 1) AliasMode, which aliases a name
    /// to another name and 2) ServiceMode, which provides connection
    /// information bound to a service endpoint domain. Placing both
    /// forms in a single RR type allows clients to fetch the relevant
    /// information with a single query.
    pub fn mode(&self) -> Mode {
        if self.priority == 0 {
            Mode::Alias
        } else {
            Mode::Service
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Svcb {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let priority = buffer.extract_u16()?;
        let target_name = buffer.extract_fqdn()?;

        let mut params = BTreeSet::new();
        while buffer.remaining() > 0 {
            let new_pos = {
                let mut remaining = buffer.sub_buffer(buffer.remaining())?;
                params.insert(Param::try_from(&mut remaining)?);
                remaining.position()
            };
            buffer.set_position(new_pos);
        }

        Ok(Self {
            priority,
            target_name,
            params,
        })
    }
}

impl RData for Svcb {
    fn record_type(&self) -> RecordType {
        RecordType::SVCB
    }

    fn into_record_data(self) -> RecordData {
        RecordData::SVCB(self)
    }
}

impl ByteConvertible for Svcb {
    fn byte_size(&self) -> usize {
        2 + self.target_name.byte_size()
            + self
                .params
                .iter()
                .fold(0, |sum, param| sum + 4 + param.byte_size())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.extend(u16::to_be_bytes(self.priority));
        buf.extend(self.target_name.to_bytes());
        for param in self.params.iter() {
            buf.extend(param.to_bytes());
        }
        buf
    }
}

pub enum Mode {
    Alias,
    Service,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ParamKey {
    Mandatory,
    Alpn,
    NoDefaultAlpn,
    Port,
    IpV4Hint,
    Ech,
    IpV6Hint,
    Private(u16),
    Invalid,
}

impl TryFrom<u16> for ParamKey {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Mandatory),
            1 => Ok(Self::Alpn),
            2 => Ok(Self::NoDefaultAlpn),
            3 => Ok(Self::Port),
            4 => Ok(Self::IpV4Hint),
            5 => Ok(Self::Ech),
            6 => Ok(Self::IpV6Hint),
            65280..=65534 => Ok(Self::Private(value)),
            65535 => Ok(Self::Invalid),
            _ => Err(DnsError::InvalidSvcbParam(value)),
        }
    }
}

impl From<ParamKey> for u16 {
    fn from(value: ParamKey) -> Self {
        match value {
            ParamKey::Mandatory => 0,
            ParamKey::Alpn => 1,
            ParamKey::NoDefaultAlpn => 2,
            ParamKey::Port => 3,
            ParamKey::IpV4Hint => 4,
            ParamKey::Ech => 5,
            ParamKey::IpV6Hint => 6,
            ParamKey::Private(val) => val,
            ParamKey::Invalid => 65535,
        }
    }
}

impl PartialOrd for ParamKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ParamKey {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Param {
    Mandatory(BTreeSet<ParamKey>),
    Alpn(Vec<Vec<u8>>),
    NoDefaultAlpn,
    Port(u16),
    IpV4Hint(Ipv4Addr),
    Ech(Vec<u8>),
    IpV6Hint(Ipv6Addr),
    Private { num: u16, bytes: Vec<u8> },
    Invalid,
}

impl Param {
    fn key(&self) -> ParamKey {
        match self {
            Self::Mandatory(_) => ParamKey::Mandatory,
            Self::Alpn(_) => ParamKey::Alpn,
            Self::NoDefaultAlpn => ParamKey::NoDefaultAlpn,
            Self::Port(_) => ParamKey::Port,
            Self::IpV4Hint(_) => ParamKey::IpV4Hint,
            Self::Ech(_) => ParamKey::Ech,
            Self::IpV6Hint(_) => ParamKey::IpV6Hint,
            Self::Private { num, bytes: _ } => ParamKey::Private(*num),
            Self::Invalid => ParamKey::Invalid,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Param {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let key = ParamKey::try_from(buffer.extract_u16()?)?;
        let mut len = buffer.extract_u16()? as usize;
        let val = match key {
            ParamKey::Mandatory => {
                let mut keys = BTreeSet::default();
                while len > 0 {
                    keys.insert(buffer.extract_u16()?.try_into()?);
                    len -= 2;
                }
                Self::Mandatory(keys)
            }
            ParamKey::Alpn => {
                let mut alpn = Vec::default();
                while len > 0 {
                    let inner_len = buffer.extract_u8()? as usize;
                    alpn.push(buffer.extract_bytes(inner_len)?.to_vec());
                    len -= inner_len + 1;
                }
                Self::Alpn(alpn)
            }
            ParamKey::NoDefaultAlpn => Self::NoDefaultAlpn,
            ParamKey::Port => Self::Port(buffer.extract_u16()?),
            ParamKey::IpV4Hint => Self::IpV4Hint(Ipv4Addr::from(buffer.extract_u32()?)),
            ParamKey::Ech => Self::Ech(buffer.extract_bytes(len)?.to_vec()),
            ParamKey::IpV6Hint => Self::IpV6Hint(Ipv6Addr::from(u128::from_be_bytes(
                buffer.extract_bytes(16)?.try_into()?,
            ))),
            ParamKey::Private(val) => Self::Private {
                num: val,
                bytes: buffer.extract_bytes(len)?.to_vec(),
            },
            ParamKey::Invalid => Self::Invalid,
        };
        Ok(val)
    }
}

impl ByteConvertible for Param {
    fn byte_size(&self) -> usize {
        4 + match self {
            Self::Mandatory(ref key_list) => key_list.len() * 2,
            Self::Alpn(ref alpns) => alpns.iter().fold(0, |acc, alpn| acc + alpn.len() + 1),
            Self::NoDefaultAlpn => 0,
            Self::Port(_) => 2,
            Self::IpV4Hint(_) => 4,
            Self::Ech(ref bytes) => bytes.len(),
            Self::IpV6Hint(_) => 16,
            Self::Private { num: _, bytes } => bytes.len(),
            Self::Invalid => 0,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let byte_size = self.byte_size();
        let mut buf = Vec::with_capacity(byte_size);

        // Add the key symbol to the serialized buffer
        let key: u16 = self.key().into();
        buf.extend(u16::to_be_bytes(key));

        // Add the param val length to the buffer
        buf.extend(u16::to_be_bytes(byte_size as u16 - 4));

        // Add the param val binary data to the buffer
        match self {
            Self::Mandatory(ref key_list) => {
                for key in key_list.iter() {
                    buf.extend(u16::to_be_bytes((*key).into()));
                }
            }
            Self::Alpn(ref alpns) => {
                for alpn in alpns.iter() {
                    buf.push(alpn.len() as u8);
                    buf.extend(alpn);
                }
            }
            Self::NoDefaultAlpn => (),
            Self::Port(port) => buf.extend(u16::to_be_bytes(*port)),
            Self::IpV4Hint(ref addr) => buf.extend(addr.octets()),
            Self::Ech(ref bytes) => buf.extend(bytes),
            Self::IpV6Hint(ref addr) => buf.extend(addr.octets()),
            Self::Private { num: _, bytes } => buf.extend(bytes),
            Self::Invalid => (),
        }
        buf
    }
}

impl PartialOrd for Param {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Param {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_key_ordering() {
        let a = ParamKey::Alpn;
        let b = ParamKey::try_from(65432).unwrap();

        assert_eq!(b, ParamKey::Private(65432));

        assert!(a < b);
        assert!(a <= b);
        assert!(b > a);
        assert!(b >= a);
    }

    #[test]
    fn parse() {
        let data = vec![
            0, 5, 4, 115, 118, 99, 52, 7, 101, 120, 97, 109, 112, 108, 101, 3, 110, 101, 116, 0, 0,
            1, 0, 4, 3, b'b', b'a', b'r', 0, 3, 0, 2, 31, 68, 0, 0, 0, 2, 0, 1,
        ];
        let svcb = Svcb::try_from(&mut DnsBuffer::from(data.as_slice())).unwrap();

        assert_eq!(svcb.priority, 5);
        assert_eq!(svcb.target_name, FQDN::new("svc4.example.net."));
        assert_eq!(
            svcb.params,
            BTreeSet::from([
                Param::Alpn(vec![vec![b'b', b'a', b'r']]),
                Param::Port(8004),
                Param::Mandatory(BTreeSet::from([ParamKey::Alpn])),
            ])
        );
    }

    #[test]
    fn build() {
        let svcb = Svcb {
            priority: 10,
            target_name: FQDN::new("foo.example.org."),
            params: BTreeSet::from([
                Param::Alpn(vec![vec![b'h', b'2'], vec![b'h', b'3', b'-', b'1', b'9']]),
                Param::Mandatory(BTreeSet::from([ParamKey::IpV4Hint, ParamKey::Alpn])),
                Param::IpV4Hint(Ipv4Addr::from([192, 0, 2, 1])),
            ]),
        };

        assert_eq!(svcb.byte_size(), 60);
        assert_eq!(
            svcb.to_bytes(),
            vec![
                0, 10, 0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x03, 0x6f, 0x72, 0x67, 0x00, 0, 0, 0, 4, 0, 1, 0, 4, 0, 1, 0, 9, 2, 0x68, 0x32, 5,
                0x68, 0x33, 0x2d, 0x31, 0x39, 0, 4, 0, 4, 0xc0, 0x00, 0x02, 0x01
            ]
        );
    }
}
