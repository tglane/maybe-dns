use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// MINFO records cause no additional section processing.  Although these
/// records can be associated with a simple mailbox, they are usually used
/// with a mailing list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minfo {
    /// A <domain-name> which specifies a mailbox which is
    /// responsible for the mailing list or mailbox.  If this
    /// domain name names the root, the owner of the MINFO RR is
    /// responsible for itself.  Note that many existing mailing
    /// lists use a mailbox X-request for the RMAILBX field of
    /// mailing list X, e.g., Msgroup-request for Msgroup.  This
    /// field provides a more general mechanism.
    pub rmailbx: FQDN,

    /// A <domain-name> which specifies a mailbox which is to
    /// receive error messages related to the mailing list or
    /// mailbox specified by the owner of the MINFO RR (similar
    /// to the ERRORS-TO: field which has been proposed).  If
    /// this domain name names the root, errors should be
    /// returned to the sender of the message.
    pub emailbx: FQDN,
}

impl Minfo {
    pub fn new(rmailbx: FQDN, emailbx: FQDN) -> Self {
        Self { rmailbx, emailbx }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Minfo {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            rmailbx: buffer.extract_fqdn()?,
            emailbx: buffer.extract_fqdn()?,
        })
    }
}

impl RData for Minfo {
    fn record_type(&self) -> RecordType {
        RecordType::MINFO
    }

    fn into_record_data(self) -> RecordData {
        RecordData::MINFO(self)
    }
}

impl ByteConvertible for Minfo {
    fn byte_size(&self) -> usize {
        self.rmailbx.byte_size() + self.emailbx.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        buffer.append(&mut self.rmailbx.to_bytes());
        buffer.append(&mut self.emailbx.to_bytes());
        buffer
    }
}

impl CompressedByteConvertible for Minfo {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        self.rmailbx.byte_size_compressed(names, offset)
            + self.emailbx.byte_size_compressed(names, offset)
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.rmailbx.to_bytes_compressed(names, offset));
        buffer.extend_from_slice(
            &self
                .emailbx
                .to_bytes_compressed(names, offset + buffer.len()),
        );
        buffer
    }
}
