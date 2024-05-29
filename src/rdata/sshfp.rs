use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{Algorithm, RData, RecordData, RecordType};

/// The SSHFP resource record (RR) is used to store a fingerprint of an
/// SSH public host key that is associated with a Domain Name System
/// (DNS) name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sshfp {
    pub algorithm: Algorithm,
    pub fingerprint_type: FingerprintType,
    pub fingerprint: Vec<u8>,
}

impl Sshfp {
    pub fn new(
        algorithm: Algorithm,
        fingerprint_type: FingerprintType,
        fingerprint: Vec<u8>,
    ) -> Self {
        Self {
            algorithm,
            fingerprint_type,
            fingerprint,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Sshfp {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            algorithm: buffer.extract_u8()?.try_into()?,
            fingerprint_type: buffer.extract_u8()?.try_into()?,
            fingerprint: buffer.extract_character_string()?,
        })
    }
}

impl RData for Sshfp {
    fn record_type(&self) -> RecordType {
        RecordType::SSHFP
    }

    fn into_record_data(self) -> RecordData {
        RecordData::SSHFP(self)
    }
}

impl ByteConvertible for Sshfp {
    fn byte_size(&self) -> usize {
        1 + 1 + self.fingerprint.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.push(self.algorithm.into());
        buff.push(self.fingerprint_type.into());
        buff.extend_from_slice(&self.fingerprint);
        buff
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FingerprintType {
    Reserved = 0,
    SHA1 = 1,
}

impl TryFrom<u8> for FingerprintType {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::SHA1),
            _ => Err(DnsError::InvalidSSHFPFingerprintType(value)),
        }
    }
}

impl From<FingerprintType> for u8 {
    fn from(fingerprint_type: FingerprintType) -> Self {
        match fingerprint_type {
            FingerprintType::Reserved => 0,
            FingerprintType::SHA1 => 1,
        }
    }
}
