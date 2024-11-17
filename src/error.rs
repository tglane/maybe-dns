use std::time::SystemTimeError;

/// Enum collection of DNS error types.
#[derive(Debug)]
pub enum DnsError {
    /// The u16 does not represent a valid DNS class.
    InvalidClass(u16),

    /// The u16 does not represent a valid DNS type.
    InvalidType(u16),

    /// The u8 does not represent a valid DNS response code.
    InvalidResponseCode(u8),

    /// Binary data does not represent a valid DNS packet
    InvalidPacketData,

    /// Binary data does not adhere to some length guidelines of the DNS standard.
    LengthViolation,

    /// Pointer used in DNS compression could not be resolved.
    UnresolveableCompressionPointer,

    /// The u16 does not represent a valid family type of APL record data.
    InvalidAplFamily(u16),

    /// The u16 does not represent a valid flag type of CSYNC record data.
    InvalidCsyncFlag(u16),

    /// The u8 does not represent a valid algorithm type of SSHFP record data.
    InvalidSSHFPAlgorithm(u8),

    /// The u8 does not represent a valid fingerprint type of SSHFP record data.
    InvalidSSHFPFingerprintType(u8),

    /// The u8 does not represent a valid gateway type of IPSECKEY record data.
    InvalidIpSecKeyGatewayType(u8),

    /// The u8 does not represent a valid flag type of NAPTR record data.
    InvalidNaptrFlag(u8),

    /// The u16 does not represent a valid mode type of TKEY record data.
    InvalidTkeyMode(u16),

    /// The u16 does not represent a valid error type of TKEY record data.
    InvalidTkeyError(u16),

    /// The u16 does not represent a valid identifier type of any record data.
    InvalidIdentifierTypeError(u16),

    /// The u8 does not represent a valid cert usage type of TLSA record data.
    InvalidTLSACertUsage(u8),

    /// The u8 does not represent a valid selector type of TLSA record data.
    InvalidTLSASelector(u8),

    /// The u8 does not represent a valid matching type of TLSA record data.
    InvalidTLSAMatchingType(u8),

    /// The u16 does not represent a valid param of SVCB record data.
    InvalidSvcbParam(u16),

    /// The u8 does not represent a valid digest type of any record data.
    InvalidDigestType(u8),

    /// The u8 does not represent a valid digest type of any record data.
    InvalidDnsSecAlgorithm(u8),

    /// DNSSEC signature is not valid.
    InvalidDnsSecSignatureTimespan(SystemTimeError),

    /// Error during verification of a DNSSEC record. The embedded string contains additional
    /// information about the error.
    DnsSecVerificationError(String),

    /// Error during signing of a DNSSEC record. The embedded string contains additional
    /// information about the error.
    DnsSecSigningError(String),
}

impl std::error::Error for DnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self)
    }
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DnsError: {:?}", &self)
    }
}

impl From<std::array::TryFromSliceError> for DnsError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::InvalidPacketData
    }
}
