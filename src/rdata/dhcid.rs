use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};
use crate::FQDN;

/// Conflicts can arise if multiple DHCP clients wish to use the same DNS
/// name or a DHCP client attempts to use a name added for another
/// purpose.  To resolve such conflicts, it is proposed to store client
/// identifiers in the DNS to unambiguously associate domain names with
/// the DHCP clients using them.  In the interest of clarity, it is
/// preferable for this DHCP information to use a distinct RR type.  This
/// memo defines a distinct RR for this purpose for use by DHCP clients
/// or servers: the "DHCID" RR.
///
/// In order to obscure potentially sensitive client identifying
/// information, the data stored is the result of a one-way SHA-256 hash
/// computation.  The hash includes information from the DHCP client's
/// message as well as the domain name itself, so that the data stored in
/// the DHCID RR will be dependent on both the client identification used
/// in the DHCP protocol interaction and the domain name.  This means
/// that the DHCID RDATA will vary if a single client is associated over
/// time with more than one name.  This makes it difficult to 'track' a
/// client as it is associated with various domain names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcid {
    /// The DHCID RR Identifier Type Code specifies what data from the DHCP
    /// client's request was used as input into the hash function. The
    /// identifier type codes are defined in the enum `IdentifierCode`.
    pub identifier_code: IdentifierType,

    /// The DHCID RR Digest Type Code is an identifier for the digest
    /// algorithm used
    /// Digest type currently only can have the value "1" which indicates SHA-256

    /// The input to the digest hash function is defined to be:
    ///     digest = SHA-256(< identifier > < FQDN >)
    /// The FQDN is represented in the buffer in the canonical wire format as.
    /// The identifier type code and the identifier are related as specified:
    /// the identifier type code describes the source of the identifier.
    pub digest: Vec<u8>,
}

impl Dhcid {
    /// Crates a new `Dhcid` record from its componets and calculates the digest
    pub fn new(identifier_code: IdentifierType, identifier: &[u8], fqdn: &FQDN) -> Self {
        use ring::digest;

        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(identifier);
        ctx.update(&fqdn.to_bytes());

        Self {
            identifier_code,
            digest: ctx.finish().as_ref().to_vec(),
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Dhcid {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let identifier_code = buffer.extract_u16()?.try_into()?;
        let digest_type_code = buffer.extract_u8()?;
        if digest_type_code != 1 {
            // Only value 1 is allowed here to represent SHA-256 digest algorithm
            return Err(DnsError::InvalidDigestType(digest_type_code));
        }
        let digest = buffer.extract_bytes(buffer.remaining())?.to_vec();
        Ok(Self {
            identifier_code,
            digest,
        })
    }
}

impl RData for Dhcid {
    fn record_type(&self) -> RecordType {
        RecordType::DHCID
    }

    fn into_record_data(self) -> RecordData {
        RecordData::DHCID(self)
    }
}

impl ByteConvertible for Dhcid {
    fn byte_size(&self) -> usize {
        std::mem::size_of::<u16>() + std::mem::size_of::<u8>() + self.digest.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.extend(u16::to_be_bytes(self.identifier_code.into()));
        buf.push(1);
        buf.extend(&self.digest);
        buf
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IdentifierType {
    ChaddrOfDhcpRequest,
    ClientIdentifierOption,
    DUID,
}

impl TryFrom<u16> for IdentifierType {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ChaddrOfDhcpRequest),
            1 => Ok(Self::ClientIdentifierOption),
            2 => Ok(Self::DUID),
            _ => Err(DnsError::InvalidIdentifierTypeError(value)),
        }
    }
}

impl From<IdentifierType> for u16 {
    fn from(value: IdentifierType) -> Self {
        match value {
            IdentifierType::ChaddrOfDhcpRequest => 0,
            IdentifierType::ClientIdentifierOption => 1,
            IdentifierType::DUID => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let data = vec![
            0x00, 0x02, 0x01, 0x63, 0x6f, 0xc0, 0xb8, 0x27, 0x1c, 0x82, 0x82, 0x5b, 0xb1, 0xac,
            0x5c, 0x41, 0xcf, 0x53, 0x51, 0xaa, 0x69, 0xb4, 0xfe, 0xbd, 0x94, 0xe8, 0xf1, 0x7c,
            0xdb, 0x95, 0x00, 0x0d, 0xa4, 0x8c, 0x40,
        ];
        let dhcid = Dhcid::try_from(&mut DnsBuffer::from(data.as_slice())).unwrap();

        assert_eq!(dhcid.identifier_code, IdentifierType::DUID);
        assert_eq!(
            dhcid.digest,
            vec![
                0x63, 0x6f, 0xc0, 0xb8, 0x27, 0x1c, 0x82, 0x82, 0x5b, 0xb1, 0xac, 0x5c, 0x41, 0xcf,
                0x53, 0x51, 0xaa, 0x69, 0xb4, 0xfe, 0xbd, 0x94, 0xe8, 0xf1, 0x7c, 0xdb, 0x95, 0x00,
                0x0d, 0xa4, 0x8c, 0x40
            ]
        );
    }

    #[test]
    fn build() {
        let dhcid = Dhcid::new(
            IdentifierType::DUID,
            &vec![
                0x00, 0x01, 0x00, 0x06, 0x41, 0x2d, 0xf1, 0x66, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            ],
            &FQDN::new("chi6.example.com"),
        );

        assert_eq!(dhcid.byte_size(), 35);
        assert_eq!(
            dhcid.to_bytes(),
            vec![
                0x00, 0x02, 0x01, 0x63, 0x6f, 0xc0, 0xb8, 0x27, 0x1c, 0x82, 0x82, 0x5b, 0xb1, 0xac,
                0x5c, 0x41, 0xcf, 0x53, 0x51, 0xaa, 0x69, 0xb4, 0xfe, 0xbd, 0x94, 0xe8, 0xf1, 0x7c,
                0xdb, 0x95, 0x00, 0x0d, 0xa4, 0x8c, 0x40
            ]
        );
    }
}
