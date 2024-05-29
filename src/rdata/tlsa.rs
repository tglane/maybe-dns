use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The TLSA DNS resource record (RR) is used to associate a TLS server
/// certificate or public key with the domain name where the record is
/// found, thus forming a "TLSA certificate association". The semantics
/// of how the TLSA RR is interpreted are given later in this document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlsa {
    /// A one-octet value, called "certificate usage", specifies the provided
    /// association that will be used to match the certificate presented in
    /// the TLS handshake.  This value is defined in a new IANA registry (see
    /// Section 7.2) in order to make it easier to add additional certificate
    /// usages in the future.
    pub cert_usage: CertUsage,

    /// A one-octet value, called "selector", specifies which part of the TLS
    /// certificate presented by the server will be matched against the
    /// association data. This value is defined in a new IANA registry (see
    /// Section 7.3).
    pub selector: Selector,

    /// A one-octet value, called "matching type", specifies how the
    /// certificate association is presented. This value is defined in a new
    /// IANA registry (see Section 7.4).
    pub matching_type: MatchingType,

    /// This field specifies the "certificate association data" to be
    /// matched.  These bytes are either raw data (that is, the full
    /// certificate or its SubjectPublicKeyInfo, depending on the selector)
    /// for matching type 0, or the hash of the raw data for matching types 1
    /// and 2.  The data refers to the certificate in the association, not to
    /// the TLS ASN.1 Certificate object.
    pub associated_data: Vec<u8>,
}

impl Tlsa {
    pub fn new(
        cert_usage: CertUsage,
        selector: Selector,
        matching_type: MatchingType,
        associated_data: Vec<u8>,
    ) -> Self {
        Self {
            cert_usage,
            selector,
            matching_type,
            associated_data,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Tlsa {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            cert_usage: buffer.extract_u8()?.try_into()?,
            selector: buffer.extract_u8()?.try_into()?,
            matching_type: buffer.extract_u8()?.try_into()?,
            associated_data: buffer.extract_bytes(buffer.remaining())?.to_vec(),
        })
    }
}

impl RData for Tlsa {
    fn record_type(&self) -> RecordType {
        RecordType::TLSA
    }

    fn into_record_data(self) -> RecordData {
        RecordData::TLSA(self)
    }
}

impl ByteConvertible for Tlsa {
    fn byte_size(&self) -> usize {
        (3 * std::mem::size_of::<u8>()) + self.associated_data.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.push(self.cert_usage.into());
        buff.push(self.selector.into());
        buff.push(self.matching_type.into());
        buff.extend_from_slice(&self.associated_data);
        buff
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CertUsage {
    Ca = 0,
    ServiceCertificateConstraint = 1,
    TrustAnchor = 2,
    DomainIssuedCertificate = 3,
}

impl TryFrom<u8> for CertUsage {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ca),
            1 => Ok(Self::ServiceCertificateConstraint),
            2 => Ok(Self::TrustAnchor),
            3 => Ok(Self::DomainIssuedCertificate),
            _ => Err(DnsError::InvalidTLSACertUsage(value)),
        }
    }
}

impl From<CertUsage> for u8 {
    fn from(selector: CertUsage) -> Self {
        match selector {
            CertUsage::Ca => 0,
            CertUsage::ServiceCertificateConstraint => 1,
            CertUsage::TrustAnchor => 2,
            CertUsage::DomainIssuedCertificate => 3,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    Full = 0,
    SubjectPublicKeyInfo = 1,
}

impl TryFrom<u8> for Selector {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::SubjectPublicKeyInfo),
            _ => Err(DnsError::InvalidSSHFPAlgorithm(value)),
        }
    }
}

impl From<Selector> for u8 {
    fn from(selector: Selector) -> Self {
        match selector {
            Selector::Full => 0,
            Selector::SubjectPublicKeyInfo => 1,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MatchingType {
    ExactMatch = 0,
    SHA256 = 1,
    SHA512 = 2,
}

impl TryFrom<u8> for MatchingType {
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

impl From<MatchingType> for u8 {
    fn from(matching_type: MatchingType) -> Self {
        match matching_type {
            MatchingType::ExactMatch => 0,
            MatchingType::SHA256 => 1,
            MatchingType::SHA512 => 2,
        }
    }
}
