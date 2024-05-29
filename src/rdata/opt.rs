use std::collections::HashMap;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// An OPT pseudo-RR (sometimes called a meta-RR) MAY be added to the
/// additional data section of a request.
/// If an OPT record is present in a received request, compliant
/// responders MUST include an OPT record in their respective responses.
///
/// An OPT record does not carry any DNS data.  It is used only to
/// contain control information pertaining to the question-and-answer
/// sequence of a specific transaction.  OPT RRs MUST NOT be cached,
/// forwarded, or stored in or loaded from master files.
///
/// The OPT RR MAY be placed anywhere within the additional data section.
/// When an OPT RR is included within any DNS message, it MUST be the
/// only OPT RR in that message.  If a query message with more than one
/// OPT RR is received, a FORMERR (RCODE=1) MUST be returned.  The
/// placement flexibility for the OPT RR does not override the need for
/// the TSIG or SIG(0) RRs to be the last in the additional section
/// whenever they are present.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Opt(pub HashMap<u16, Vec<u8>>);

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Opt {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let mut this = Self(HashMap::new());
        while buffer.remaining() > 0 {
            let opt_code = buffer.extract_u16()?;
            let opt_data_len = buffer.extract_u16()?;
            let opt_data = buffer.extract_bytes(opt_data_len as usize)?;
            this.0.insert(opt_code, opt_data.to_vec());
        }
        Ok(this)
    }
}

impl RData for Opt {
    fn record_type(&self) -> RecordType {
        RecordType::OPT
    }

    fn into_record_data(self) -> RecordData {
        RecordData::OPT(self)
    }
}

impl ByteConvertible for Opt {
    fn byte_size(&self) -> usize {
        (2 * std::mem::size_of::<u8>()) + self.0.iter().fold(0, |acc, elem| acc + elem.1.len())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::with_capacity(self.byte_size());
        for (code, data) in self.0.iter() {
            buff.extend_from_slice(&u16::to_be_bytes(*code));
            buff.extend_from_slice(&u16::to_be_bytes(data.len() as u16));
            buff.extend_from_slice(data);
        }
        buff
    }
}
