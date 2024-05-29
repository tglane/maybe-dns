use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// NAPTR records are most commonly used for applications in Internet
/// telephony, for example, in the mapping of servers and user addresses
/// in the Session Initiation Protocol (SIP). The combination of NAPTR
/// records with Service Records (SRV) allows the chaining of multiple
/// records to form complex rewrite rules which produce new domain labels
/// or uniform resource identifiers (URIs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Naptr {
    /// Specifies the order in which the NAPTR records must be processed
    /// to ensure the correct ordering of rules. Low numbers are processed
    /// before high numbers, and once a NAPTR is found whose rule "matches"
    /// the target, the client MUST NOT consider any NAPTRs with a higher
    /// value for order (except as noted below for the Flags field).
    order: u16,

    /// A 16-bit unsigned integer that specifies the order in which NAPTR
    /// records with equal "order" values SHOULD be processed, low
    /// numbers being processed before high numbers.  This is similar to
    /// the preference field in an MX record, and is used so domain
    /// administrators can direct clients towards more capable hosts or
    /// lighter weight protocols.  A client MAY look at records with
    /// higher preference values if it has a good reason to do so such as
    /// not understanding the preferred protocol or service.
    ///
    /// The important difference between Order and Preference is that
    /// once a match is found the client MUST NOT consider records with a
    /// different Order but they MAY process records with the same Order
    /// but different Preferences.  I.e., Preference is used to give weight
    /// to rules that are considered the same from an authority
    /// standpoint but not from a simple load balancing standpoint.
    preference: u16,

    /// A <character-string> containing flags to control aspects of the
    /// rewriting and interpretation of the fields in the record.  Flags
    /// are single characters from the set [A-Z0-9].  The case of the
    /// alphabetic characters is not significant.
    flags: Vec<Flag>,

    /// Specifies the service(s) available down this rewrite path.  It may
    /// also specify the particular protocol that is used to talk with a
    /// service.  A protocol MUST be specified if the flags field states
    /// that the NAPTR is terminal.  If a protocol is specified, but the
    /// flags field does not state that the NAPTR is terminal, the next
    /// lookup MUST be for a NAPTR.  The client MAY choose not to perform
    /// the next lookup if the protocol is unknown, but that behavior
    /// MUST NOT be relied upon.
    service: Vec<u8>,

    /// A STRING containing a substitution expression that is applied to
    /// the original string held by the client in order to construct the
    /// next domain name to lookup.  The grammar of the substitution
    /// expression is given in the next section.
    regexp: String,

    /// The next NAME to query for NAPTR, SRV, or address records
    /// depending on the value of the flags field.  This MUST be a fully
    /// qualified domain-name. Unless and until permitted by future
    /// standards action, name compression is not to be used for this
    /// field.
    replacement: FQDN,
}

impl Naptr {
    pub fn new(
        order: u16,
        preference: u16,
        flags: Vec<Flag>,
        service: Vec<u8>,
        regexp: String,
        replacement: FQDN,
    ) -> Self {
        Self {
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Naptr {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            order: buffer.extract_u16()?,
            preference: buffer.extract_u16()?,
            flags: buffer
                .extract_character_string()?
                .iter()
                .flat_map(|ch| Flag::try_from(*ch))
                .collect(),
            service: buffer.extract_character_string()?,
            regexp: buffer.extract_string()?,
            replacement: buffer.extract_fqdn()?,
        })
    }
}

impl RData for Naptr {
    fn record_type(&self) -> RecordType {
        RecordType::NAPTR
    }

    fn into_record_data(self) -> RecordData {
        RecordData::NAPTR(self)
    }
}

impl ByteConvertible for Naptr {
    fn byte_size(&self) -> usize {
        (2 * std::mem::size_of::<u16>())
            + (3 * std::mem::size_of::<u8>())
            + self.flags.len()
            + self.service.len()
            + self.regexp.len()
            + self.replacement.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.extend_from_slice(&u16::to_be_bytes(self.order));
        buff.extend_from_slice(&u16::to_be_bytes(self.preference));
        buff.push(self.flags.len() as u8);
        buff.append(&mut self.flags.iter().map(|f| u8::from(*f)).collect::<Vec<u8>>());
        buff.push(self.service.len() as u8);
        buff.extend_from_slice(&self.service);
        buff.push(self.regexp.len() as u8);
        buff.extend_from_slice(self.regexp.as_bytes());
        buff.append(&mut self.replacement.to_bytes());
        buff
    }
}

impl CompressedByteConvertible for Naptr {
    fn byte_size_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> usize {
        let mut size = (2 * std::mem::size_of::<u16>())
            + (3 * std::mem::size_of::<u8>())
            + self.flags.len()
            + self.service.len()
            + self.regexp.len();
        size += self.replacement.byte_size_compressed(names, offset + size);
        size
    }

    fn to_bytes_compressed(&self, names: &mut HashMap<u64, usize>, offset: usize) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        buff.extend_from_slice(&u16::to_be_bytes(self.order));
        buff.extend_from_slice(&u16::to_be_bytes(self.preference));
        buff.push(self.flags.len() as u8);
        buff.append(&mut self.flags.iter().map(|f| u8::from(*f)).collect::<Vec<u8>>());
        buff.push(self.service.len() as u8);
        buff.extend_from_slice(&self.service);
        buff.push(self.regexp.len() as u8);
        buff.extend_from_slice(self.regexp.as_bytes());
        buff.append(
            &mut self
                .replacement
                .to_bytes_compressed(names, offset + buff.len()),
        );
        buff
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Flag {
    S,
    A,
    U,
    P,
}

impl TryFrom<u8> for Flag {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value as char {
            'S' => Ok(Self::S),
            'A' => Ok(Self::A),
            'U' => Ok(Self::U),
            'P' => Ok(Self::P),
            _ => Err(DnsError::InvalidNaptrFlag(value)),
        }
    }
}

impl From<Flag> for u8 {
    fn from(value: Flag) -> Self {
        match value {
            Flag::S => b'S',
            Flag::A => b'A',
            Flag::U => b'U',
            Flag::P => b'P',
        }
    }
}
