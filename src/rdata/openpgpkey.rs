use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The OPENPGPKEY DNS resource record (RR) is used to associate an end
/// entity OpenPGP Transferable Public Key (see Section 11.1 of
/// [RFC4880]) with an email address, thus forming an "OpenPGP public key
/// association".  A user that wishes to specify more than one OpenPGP
/// key, for example, because they are transitioning to a newer stronger
/// key, can do so by adding multiple OPENPGPKEY records.  A single
/// OPENPGPKEY DNS record MUST only contain one OpenPGP key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenPgpKey(pub Vec<u8>);

impl<'a> TryFrom<&mut DnsBuffer<'a>> for OpenPgpKey {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self(buffer.extract_bytes(buffer.remaining())?.to_vec()))
    }
}

impl RData for OpenPgpKey {
    fn record_type(&self) -> RecordType {
        RecordType::OPENPGPKEY
    }

    fn into_record_data(self) -> RecordData {
        RecordData::OPENPGPKEY(self)
    }
}

impl ByteConvertible for OpenPgpKey {
    fn byte_size(&self) -> usize {
        self.0.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}
