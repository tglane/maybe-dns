use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tkey {
    /// The algorithm name is in the form of a domain name with the same
    /// meaning as in [RFC 2845]. The algorithm determines how the secret
    /// keying material agreed to using the TKEY RR is actually used to
    /// derive the algorithm specific key. This MUST NOT be compressed.
    pub algorithm: FQDN,

    /// Number of seconds since the beginning of 1 January
    /// 1970 GMT ignoring leap seconds
    pub inception: u32,

    /// Number of seconds since the beginning of 1 January
    /// 1970 GMT ignoring leap seconds
    pub expiration: u32,

    /// The mode field specifies the general scheme for key agreement or the
    /// purpose of the TKEY DNS message.
    pub mode: Mode,

    /// When the TKEY Error Field is non-zero in a response to a TKEY query,
    /// the DNS header RCODE field indicates no error. However, it is
    /// possible if a TKEY is spontaneously included in a response the TKEY
    /// RR and DNS header error field could have unrelated non-zero error
    /// codes.
    pub error: Error,

    /// The meaning of this data depends on the mode.
    pub key_data: Vec<u8>,

    /// The Other Size and Other Data fields are not used in this
    /// specification but may be used in future extensions.
    pub other_data: Vec<u8>,
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Tkey {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let algorithm = buffer.extract_fqdn()?;
        let inception = buffer.extract_u32()?;
        let expiration = buffer.extract_u32()?;
        let mode = buffer.extract_u16()?.try_into()?;
        let error = buffer.extract_u16()?.try_into()?;
        let key_size = buffer.extract_u16()?;
        let key_data = buffer.extract_bytes(key_size as usize)?.to_vec();
        let other_size = buffer.extract_u16()?;
        let other_data = buffer.extract_bytes(other_size as usize)?.to_vec();

        Ok(Self {
            algorithm,
            inception,
            expiration,
            mode,
            error,
            key_data,
            other_data,
        })
    }
}

impl RData for Tkey {
    fn record_type(&self) -> RecordType {
        RecordType::TKEY
    }

    fn into_record_data(self) -> RecordData {
        RecordData::TKEY(self)
    }
}

impl ByteConvertible for Tkey {
    fn byte_size(&self) -> usize {
        self.algorithm.byte_size()
            + (2 * std::mem::size_of::<u32>())
            + (4 * std::mem::size_of::<u16>())
            + self.key_data.len()
            + self.other_data.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.extend(self.algorithm.to_bytes());
        buf.extend(u32::to_be_bytes(self.inception));
        buf.extend(u32::to_be_bytes(self.expiration));
        buf.extend(u16::to_be_bytes(self.mode.into()));
        buf.extend(u16::to_be_bytes(self.error.into()));
        buf.extend(u16::to_be_bytes(self.key_data.len() as u16));
        buf.extend_from_slice(&self.key_data);
        buf.extend(u16::to_be_bytes(self.other_data.len() as u16));
        buf.extend_from_slice(&self.other_data);
        buf
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    ServerAssignment,
    DiffieHellmanExchange,
    GssApiNegotiation,
    ResolverAssignment,
    KeyDeletion,
    Available(u16),
}

impl TryFrom<u16> for Mode {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ServerAssignment),
            2 => Ok(Self::DiffieHellmanExchange),
            3 => Ok(Self::GssApiNegotiation),
            4 => Ok(Self::ResolverAssignment),
            5 => Ok(Self::KeyDeletion),
            6..=65534 => Ok(Self::Available(value)),
            _ => Err(DnsError::InvalidTkeyMode(value)),
        }
    }
}

impl From<Mode> for u16 {
    fn from(value: Mode) -> Self {
        match value {
            Mode::ServerAssignment => 1,
            Mode::DiffieHellmanExchange => 2,
            Mode::GssApiNegotiation => 3,
            Mode::ResolverAssignment => 4,
            Mode::KeyDeletion => 5,
            Mode::Available(value) => value,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    None,
    NonExtendedRcode(u16),
    BadSig,
    BadKey,
    BadTime,
    BadMode,
    BadName,
    BadAlg,
}

impl TryFrom<u16> for Error {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1..=15 => Ok(Self::NonExtendedRcode(value)),
            16 => Ok(Self::BadSig),
            17 => Ok(Self::BadKey),
            18 => Ok(Self::BadTime),
            19 => Ok(Self::BadMode),
            20 => Ok(Self::BadName),
            21 => Ok(Self::BadAlg),
            _ => Err(DnsError::InvalidTkeyError(value)),
        }
    }
}

impl From<Error> for u16 {
    fn from(value: Error) -> Self {
        match value {
            Error::None => 0,
            Error::NonExtendedRcode(value) => value,
            Error::BadSig => 16,
            Error::BadKey => 17,
            Error::BadTime => 18,
            Error::BadMode => 19,
            Error::BadName => 20,
            Error::BadAlg => 21,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let data = vec![
            13, 56, 57, 110, 51, 109, 68, 103, 88, 48, 55, 50, 112, 112, 7, 115, 101, 114, 118,
            101, 114, 49, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 0, 48, 57, 0,
            0, 221, 213, 0, 2, 0, 0, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0,
        ];
        let tkey = Tkey::try_from(&mut DnsBuffer::from(data.as_slice())).unwrap();

        assert_eq!(
            tkey.algorithm,
            FQDN::from("89n3mDgX072pp.server1.example.com")
        );
        assert_eq!(tkey.inception, 12345);
        assert_eq!(tkey.expiration, 56789);
        assert_eq!(tkey.mode, Mode::DiffieHellmanExchange);
        assert_eq!(tkey.error, Error::None);
        assert_eq!(tkey.key_data, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(tkey.other_data, vec![]);
    }

    #[test]
    fn build() {
        let tkey = Tkey {
            algorithm: FQDN::from("89n3mDgX072pp.server1.example.com"),
            inception: 12345,
            expiration: 56789,
            mode: Mode::DiffieHellmanExchange,
            error: Error::None,
            key_data: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            other_data: Vec::default(),
        };

        assert_eq!(tkey.byte_size(), 61);
        assert_eq!(tkey.byte_size(), tkey.to_bytes().len());

        assert_eq!(
            tkey.to_bytes(),
            vec![
                13, 56, 57, 110, 51, 109, 68, 103, 88, 48, 55, 50, 112, 112, 7, 115, 101, 114, 118,
                101, 114, 49, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 0, 48,
                57, 0, 0, 221, 213, 0, 2, 0, 0, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0
            ]
        );
    }
}
