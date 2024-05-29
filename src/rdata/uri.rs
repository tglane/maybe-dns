use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// Just like the SRV RR [RFC2782], the URI RR has service information
/// encoded in its owner name. In order to encode the service for a
/// specific owner name, one uses service parameters.  Valid service
/// parameters are those registered by IANA in the "Service Name and
/// Transport Protocol Port Number Registry" [RFC6335] or as "Enumservice
/// Registrations [RFC6117]. The Enumservice Registration parameters are
/// reversed (i.e., subtype(s) before type), prepended with an underscore
/// (_), and prepended to the owner name in separate labels. The
/// underscore is prepended to the service parameters to avoid collisions
/// with DNS labels that occur in nature, and the order is reversed to
/// make it possible to do delegations, if needed, to different zones
/// (and therefore providers of DNS).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Uri {
    /// This field holds the priority of the target URI in this RR.  Its
    /// range is 0-65535.  A client MUST attempt to contact the URI with the
    /// lowest-numbered priority it can reach; URIs with the same priority
    /// SHOULD be selected according to probabilities defined by the weight
    /// field.
    pub priority: u16,

    /// This field holds the server selection mechanism.  The weight field
    /// specifies a relative weight for entries with the same priority.
    /// Larger weights SHOULD be given a proportionately higher probability
    /// of being selected. The range of this number is 0-65535.
    pub weight: u16,

    /// This field holds the URI of the target, enclosed in double-quote
    /// characters ('"'), where the URI is as specified in RFC 3986
    /// [RFC3986]. Resolution of the URI is according to the definitions for
    /// the Scheme of the URI.
    pub target: Vec<u8>,
}

impl Uri {
    pub fn new(priority: u16, weight: u16, target: Vec<u8>) -> Self {
        Self {
            priority,
            weight,
            target,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Uri {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            priority: buffer.extract_u16()?,
            weight: buffer.extract_u16()?,
            target: buffer.extract_bytes(buffer.remaining())?.to_vec(),
        })
    }
}

impl RData for Uri {
    fn record_type(&self) -> RecordType {
        RecordType::URI
    }

    fn into_record_data(self) -> RecordData {
        RecordData::URI(self)
    }
}

impl ByteConvertible for Uri {
    fn byte_size(&self) -> usize {
        (2 * std::mem::size_of::<u16>()) + self.target.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.extend_from_slice(&u16::to_be_bytes(self.priority));
        buff.extend_from_slice(&u16::to_be_bytes(self.weight));
        buff.extend_from_slice(&self.target);
        buff
    }
}
