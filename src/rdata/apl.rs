use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The Domain Name System [RFC1034], [RFC1035] provides a mechanism to
/// associate addresses and other Internet infrastructure elements with
/// hierarchically built domain names.  Various types of resource records
/// have been defined, especially those for IPv4 and IPv6 [RFC2874]
/// addresses.  In [RFC1101] a method is described to publish information
/// about the address space allocated to an organisation.  In older BIND
/// versions, a weak form of controlling access to zone data was
/// implemented using TXT RRs describing address ranges.
///
/// This document specifies a new RR type for address prefix lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Apl {
    /// Upper and lower bounds and interpretation of
    /// this value are address family specific.
    pub prefix: u8,

    /// Negation flag, indicates the presence of the
    /// "!" character in the textual format. It has
    /// the value "1" if the "!" was given, "0" else.
    pub n: bool,

    /// Address family dependent part. This document defines
    /// the AFDPARTs for address families 1 (IPv4) and 2 (IPv6).
    /// Future revisions may deal with additional address
    /// families.
    pub afd_part: Afd,
}

impl Apl {
    pub fn new(prefix: u8, n: bool, afd_part: Afd) -> Self {
        Self {
            prefix,
            n,
            afd_part,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Apl {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let family = buffer.extract_u16()?;
        let prefix = buffer.extract_u8()?;
        let coded_byte = buffer.extract_u8()?;
        let n = coded_byte & 0x80 != 0;
        let mut afd_bytes = buffer.extract_bytes((coded_byte & 0x7E) as usize)?.to_vec();

        let afd_part = match family {
            1 => {
                afd_bytes.resize(4, 0);
                Afd::IpV4(Ipv4Addr::new(
                    afd_bytes[0],
                    afd_bytes[1],
                    afd_bytes[2],
                    afd_bytes[3],
                ))
            }
            2 => {
                afd_bytes.resize(16, 0);
                Afd::IpV6(Ipv6Addr::from(u128::from_be_bytes(
                    afd_bytes.try_into().expect("Resized to 16 bytes before"),
                )))
            }
            val => return Err(DnsError::InvalidAplFamily(val)),
        };

        Ok(Self {
            prefix,
            n,
            afd_part,
        })
    }
}

impl RData for Apl {
    fn record_type(&self) -> RecordType {
        RecordType::APL
    }

    fn into_record_data(self) -> RecordData {
        RecordData::APL(self)
    }
}

impl ByteConvertible for Apl {
    fn byte_size(&self) -> usize {
        (2 * std::mem::size_of::<u16>()) + self.afd_part.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.extend(u16::to_be_bytes(self.afd_part.binary_family_repr()));
        buff.push(self.prefix);
        buff.push((self.n as u8) << 7 | self.afd_part.byte_size() as u8);
        buff.extend(self.afd_part.to_bytes());
        buff
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Afd {
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
}

impl Afd {
    fn binary_family_repr(&self) -> u16 {
        match self {
            Self::IpV4(_) => 1,
            Self::IpV6(_) => 2,
        }
    }
}

impl ByteConvertible for Afd {
    fn byte_size(&self) -> usize {
        match self {
            Self::IpV4(_) => 4,
            Self::IpV6(_) => 16,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        match self {
            Self::IpV4(ref v4) => buf.extend(v4.octets()),
            Self::IpV6(ref v6) => buf.extend(v6.octets()),
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, str::FromStr};

    #[test]
    fn parse() {
        let bin_data = vec![0, 1, 4, 132, 192, 168, 178, 12];
        let apl = Apl::try_from(&mut DnsBuffer::from(bin_data.as_ref())).unwrap();

        assert_eq!(apl.n, true);
        assert_eq!(apl.prefix, 4);
        assert_eq!(
            apl.afd_part,
            Afd::IpV4(Ipv4Addr::from_str("192.168.178.12").unwrap())
        );
    }

    #[test]
    fn build() {
        let ip = Ipv4Addr::from_str("192.168.178.12").unwrap();
        let afd = Afd::IpV4(ip);

        let apl = Apl::new(4, true, afd);

        assert_eq!(apl.byte_size(), 8);
        assert_eq!(apl.to_bytes(), vec![0, 1, 4, 132, 192, 168, 178, 12]);
    }
}
