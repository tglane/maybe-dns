use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{Algorithm, RData, RecordData, RecordType};

/// The IPSECKEY resource record (RR) is used to publish a public key
/// that is to be associated with a Domain Name System (DNS) name for
/// use with the IPsec protocol suite.  This can be the public key of a
/// host, network, or application (in the case of per-port keying).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpSecKey {
    /// Gateways listed in IPSECKEY records with lower precedence are to be
    /// attempted first.  Where there is a tie in precedence, the order
    /// should be non-deterministic.
    pub precedence: u8,

    /// The algorithm type field identifies the public key's cryptographic
    /// algorithm and determines the format of the public key field.
    pub algorithm: Algorithm,

    /// The gateway field indicates a gateway to which an IPsec tunnel may be
    /// created in order to reach the entity named by this resource record.
    pub gateway: Gateway,

    pub public_key: Vec<u8>,
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for IpSecKey {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let precedence = buffer.extract_u8()?;
        let gateway_type = buffer.extract_u8()?;
        let algorithm = buffer.extract_u8()?.try_into()?;
        let gateway = match gateway_type {
            0 => {
                // Empty gateway type but we need to extract one byte that is always present as
                // gateway data even if it is emtpy
                buffer.extract_u8()?;
                Gateway::None
            }
            1 => Gateway::IpV4(Ipv4Addr::from(buffer.extract_u32()?)),
            2 => Gateway::IpV6(Ipv6Addr::from(u128::from_be_bytes(
                buffer.extract_bytes(16)?.try_into()?,
            ))),
            3 => Gateway::Domain(buffer.extract_fqdn()?),
            val => return Err(DnsError::InvalidIpSecKeyGatewayType(val)),
        };
        let public_key = buffer.extract_bytes(buffer.remaining())?.to_vec();
        Ok(Self {
            precedence,
            algorithm,
            gateway,
            public_key,
        })
    }
}

impl RData for IpSecKey {
    fn record_type(&self) -> RecordType {
        RecordType::IPSECKEY
    }

    fn into_record_data(self) -> RecordData {
        RecordData::IPSECKEY(self)
    }
}

impl ByteConvertible for IpSecKey {
    fn byte_size(&self) -> usize {
        3 + self.gateway.byte_size() + self.public_key.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.push(self.precedence);
        buf.push(self.gateway.gateway_type());
        buf.push(self.algorithm.into());
        buf.extend(self.gateway.to_bytes());
        buf.extend(&self.public_key);
        buf
    }
}

/// The gateway field indicates a gateway to which an IPsec tunnel may be
/// created in order to reach the entity named by this resource record.
/// There are three formats:
///
/// A 32-bit IPv4 address is present in the gateway field. The data
/// portion is an IPv4 address as described in section 3.4.1 of RFC 1035.
/// This is a 32-bit number in network byte order.
///
/// A 128-bit IPv6 address is present in the gateway field. The data
/// portion is an IPv6 address as described in section 2.2 of RFC 3596.
/// This is a 128-bit number in network byte order.
///
/// The gateway field is a normal wire-encoded domain name, as described
/// in section 3.3 of RFC 1035. Compression MUST NOT be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gateway {
    None,
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
    Domain(FQDN),
}

impl Gateway {
    pub fn gateway_type(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::IpV4(_) => 1,
            Self::IpV6(_) => 2,
            Self::Domain(_) => 3,
        }
    }
}

impl ByteConvertible for Gateway {
    fn byte_size(&self) -> usize {
        match &self {
            Self::None => 1,
            Self::IpV4(_) => 4,
            Self::IpV6(_) => 16,
            Self::Domain(ref name) => name.byte_size(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match &self {
            Self::None => vec![b'.'],
            Self::IpV4(ref addr) => addr.octets().to_vec(),
            Self::IpV6(ref addr) => addr.octets().to_vec(),
            Self::Domain(ref name) => name.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let mut data = vec![10, 0, 2, b'.'];
        data.extend(b"AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==");

        let ipseckey = IpSecKey::try_from(&mut DnsBuffer::from(data.as_slice())).unwrap();
        assert_eq!(ipseckey.gateway.gateway_type(), 0);
        assert_eq!(ipseckey.precedence, 10);
        assert_eq!(ipseckey.algorithm, Algorithm::DSA);
        assert_eq!(ipseckey.gateway, Gateway::None);

        assert_eq!(ipseckey.byte_size(), data.len());
        assert_eq!(ipseckey.to_bytes(), data);
    }

    #[test]
    fn build() {
        let ipseckey = IpSecKey {
            precedence: 10,
            algorithm: 2.try_into().unwrap(),
            gateway: Gateway::IpV4(Ipv4Addr::from([192, 0, 2, 38])),
            public_key: b"AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==".to_vec(),
        };

        assert_eq!(
            ipseckey.to_bytes(),
            vec![
                10, 1, 2, 192, 0, 2, 38, 65, 81, 78, 82, 85, 51, 109, 71, 55, 84, 86, 84, 79, 50,
                66, 107, 82, 52, 55, 117, 115, 110, 116, 98, 49, 48, 50, 117, 70, 74, 116, 117,
                103, 98, 111, 54, 66, 83, 71, 118, 103, 113, 116, 52, 65, 81, 61, 61
            ]
        );
    }
}
