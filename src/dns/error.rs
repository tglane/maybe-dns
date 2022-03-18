#[derive(Debug)]
pub enum DnsError {
    InvalidClass(u16),
    InvalidType(u16),
    InvalidPacketData,
}

// TODO Implement conversions

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
