#[derive(Debug)]
pub enum DnsError {
    InvalidClass(u16),
    InvalidType(u16),
    InvalidResponseCode(u8),
    InvalidPacketData,
    LengthViolation,
    UnresolveableCompressionPointer,
    InvalidSSHFPAlgorithm(u8),
    InvalidSSHFPFingerprintType(u8),
    InvalidTLSASelector(u8),
    InvalidTLSAMatchingType(u8),
    InvalidDNSKEYAlgorithm(u8),
}

impl std::error::Error for DnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self)
    }
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DnsError: {}", &self)
    }
}

impl From<std::array::TryFromSliceError> for DnsError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::InvalidPacketData
    }
}
