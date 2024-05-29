use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// The SRV RR allows administrators to use several servers for a single
/// domain, to move services from host to host with little fuss, and to
/// designate some hosts as primary servers for a service and others as
/// backups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Srv {
    /// The priority of this target host.  A client MUST attempt to
    /// contact the target host with the lowest-numbered priority it can
    /// reach; target hosts with the same priority SHOULD be tried in an
    /// order defined by the weight field.  The range is 0-65535.  This
    /// is a 16 bit unsigned integer in network byte order.
    pub priority: u16,

    /// A server selection mechanism.  The weight field specifies a
    /// relative weight for entries with the same priority. Larger
    /// weights SHOULD be given a proportionately higher probability of
    /// being selected. The range of this number is 0-65535.  This is a
    /// 16 bit unsigned integer in network byte order.  Domain
    /// administrators SHOULD use Weight 0 when there isn't any server
    /// selection to do, to make the RR easier to read for humans (less
    /// noisy).  In the presence of records containing weights greater
    /// than 0, records with weight 0 should have a very small chance of
    /// being selected.
    pub weight: u16,

    /// The port on this target host of this service.  The range is 0-
    /// 65535.  This is a 16 bit unsigned integer in network byte order.
    /// This is often as specified in Assigned Numbers but need not be.
    pub port: u16,

    /// The domain name of the target host.  There MUST be one or more
    /// address records for this name, the name MUST NOT be an alias (in
    /// the sense of RFC 1034 or RFC 2181).  Implementors are urged, but
    /// not required, to return the address record(s) in the Additional
    /// Data section.  Unless and until permitted by future standards
    /// action, name compression is not to be used for this field.
    ///
    /// A Target of "." means that the service is decidedly not
    /// available at this domain.
    pub target: FQDN,
}

impl Srv {
    pub fn new(priority: u16, weight: u16, port: u16, target: FQDN) -> Self {
        Self {
            priority,
            weight,
            port,
            target,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Srv {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            priority: buffer.extract_u16()?,
            weight: buffer.extract_u16()?,
            port: buffer.extract_u16()?,
            target: buffer.extract_fqdn()?,
        })
    }
}

impl RData for Srv {
    fn record_type(&self) -> RecordType {
        RecordType::SRV
    }

    fn into_record_data(self) -> RecordData {
        RecordData::SRV(self)
    }
}

impl ByteConvertible for Srv {
    fn byte_size(&self) -> usize {
        (3 * std::mem::size_of::<u16>()) + self.target.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.extend_from_slice(&u16::to_be_bytes(self.priority));
        buff.extend_from_slice(&u16::to_be_bytes(self.weight));
        buff.extend_from_slice(&u16::to_be_bytes(self.port));
        buff.append(&mut self.target.to_bytes());
        buff
    }
}

impl CompressedByteConvertible for Srv {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        (3 * std::mem::size_of::<u16>()) + self.target.byte_size_compressed(names, offset + 6)
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        let mut buff = Vec::new();
        buff.extend_from_slice(&u16::to_be_bytes(self.priority));
        buff.extend_from_slice(&u16::to_be_bytes(self.weight));
        buff.extend_from_slice(&u16::to_be_bytes(self.port));
        buff.append(&mut self.target.to_bytes_compressed(names, offset + 6));
        buff
    }
}
