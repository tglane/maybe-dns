use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{RData, RecordData, RecordType};

/// To provide secret key authentication, we use an RR type whose mnemonic
/// is TSIG and whose type code is 250. TSIG is a meta-RR and MUST NOT be
/// cached. TSIG RRs are used for authentication between DNS entities that
/// have established a shared secret key. TSIG RRs are dynamically computed to
/// cover a particular DNS transaction and are not DNS RRs in the usual sense.
/// As the TSIG RRs are related to one DNS request/response, there is no value
/// in storing or retransmitting them; thus, the TSIG RR is discarded once it
/// has been used to authenticate a DNS message.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tsig {
    /// Octet sequence identifying the TSIG algorithm in the
    /// domain name syntax. (Allowed names are listed in Table 3.)
    /// The name is stored in the DNS name wire format as described
    /// in [RFC1034]. As per [RFC3597], this name MUST NOT be compressed
    pub algorithm: FQDN,

    /// An unsigned 48-bit integer containing the time the message was
    /// signed as seconds since 00:00 on 1970-01-01 UTC, ignoring leap
    /// seconds
    pub time_signed: u64,

    /// An unsigned 16-bit integer specifying the allowed time difference
    /// in seconds permitted in the Time Signed field
    pub fudge: u16,

    /// A sequence of octets whose contents are defined by the TSIG
    /// algorithm used, possibly truncated as specified by the MAC Size.
    /// The length of this field is given by the MAC Size.
    pub mac: Vec<u8>,

    /// An unsigned 16-bit integer holding the message ID of the original
    /// request message. For a TSIG RR on a request, it is set equal to
    /// the DNS message ID. In a TSIG attached to a response -- or in
    /// cases such as the forwarding of a dynamic update request --
    /// the field contains the ID of the original DNS request
    pub original_id: u16,

    /// In responses, an unsigned 16-bit integer containing the extended
    /// RCODE covering TSIG processing. In requests, this MUST be zero
    pub error: Error,

    /// Additional data relevant to the TSIG record. In responses, this
    /// will be empty (i.e., Other Len will be zero) unless the content
    /// of the Error field is BADTIME, in which case it will be a 48-bit
    /// unsigned integer containing the server's current time as the number
    /// of seconds since 00:00 on 1970-01-01 UTC, ignoring leap seconds
    /// (see Section 5.2.3). The content has no pre-defined meaning in
    /// requests
    pub other_data: Vec<u8>,
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Tsig {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let algorithm = buffer.extract_fqdn()?;
        let mut time_signed_extended = [0_u8; std::mem::size_of::<u64>()];
        time_signed_extended[2..].copy_from_slice(buffer.extract_bytes(6)?);
        let fudge = buffer.extract_u16()?;
        let mac_len = buffer.extract_u16()?;
        let mac = buffer.extract_bytes(mac_len as usize)?.to_vec();
        let original_id = buffer.extract_u16()?;
        let error = buffer.extract_u16()?.try_into()?;
        let other_len = buffer.extract_u16()?;
        let other_data = buffer.extract_bytes(other_len as usize)?.to_vec();

        Ok(Self {
            algorithm,
            time_signed: u64::from_be_bytes(time_signed_extended),
            fudge,
            mac,
            original_id,
            error,
            other_data,
        })
    }
}

impl RData for Tsig {
    fn record_type(&self) -> RecordType {
        RecordType::TSIG
    }

    fn into_record_data(self) -> RecordData {
        RecordData::TSIG(self)
    }
}

impl ByteConvertible for Tsig {
    fn byte_size(&self) -> usize {
        self.algorithm.byte_size()
            + 6
            + (5 * std::mem::size_of::<u16>())
            + self.mac.len()
            + self.other_data.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        println!("Test: {:?}", self.algorithm.to_bytes());
        buf.extend(self.algorithm.to_bytes());
        buf.extend(&self.time_signed.to_be_bytes()[2..]); // 48 bytes
        buf.extend(self.fudge.to_be_bytes()); // 16 b
        buf.extend(u16::to_be_bytes(self.mac.len() as u16)); // 16 b
        buf.extend(&self.mac);
        buf.extend(self.original_id.to_be_bytes()); // 16 b
        buf.extend(u16::to_be_bytes(self.error.into())); // 16 b
        buf.extend(u16::to_be_bytes(self.other_data.len() as u16)); // 16 b
        buf.extend(&self.other_data);
        buf
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    None,
    BadSig,
    BadKey,
    BadTime,
    BadTrunc,
}

impl TryFrom<u16> for Error {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            16 => Ok(Self::BadSig),
            17 => Ok(Self::BadKey),
            18 => Ok(Self::BadTime),
            22 => Ok(Self::BadTrunc),
            _ => Err(DnsError::InvalidTkeyError(value)),
        }
    }
}

impl From<Error> for u16 {
    fn from(value: Error) -> Self {
        match value {
            Error::None => 0,
            Error::BadSig => 16,
            Error::BadKey => 17,
            Error::BadTime => 18,
            Error::BadTrunc => 22,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let data = vec![
            8, 72, 77, 65, 67, 45, 77, 68, 53, 7, 83, 73, 71, 45, 65, 76, 71, 3, 82, 69, 71, 3, 73,
            78, 84, 0, 0, 0, 102, 79, 162, 15, 0, 15, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0,
            0, 0, 3, 11, 22, 33,
        ];
        let tsig = Tsig::try_from(&mut DnsBuffer::from(data.as_slice())).unwrap();

        assert_eq!(tsig.algorithm, FQDN::from("HMAC-MD5.SIG-ALG.REG.INT"));
        assert_eq!(tsig.time_signed, 1716494863);
        assert_eq!(tsig.fudge, 15);
        assert_eq!(tsig.mac, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(tsig.original_id, 1);
        assert_eq!(tsig.error, Error::None);
        assert_eq!(tsig.other_data, vec![11, 22, 33]);
    }

    #[test]
    fn build() {
        let tsig = Tsig {
            algorithm: FQDN::from("HMAC-MD5.SIG-ALG.REG.INT"),
            time_signed: 1716494863,
            fudge: 15,
            mac: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            original_id: 1,
            error: Error::None,
            other_data: vec![11, 22, 33],
        };

        let expected_len = tsig.algorithm.byte_size()
            + 6
            + (5 * std::mem::size_of::<u16>())
            + tsig.mac.len()
            + tsig.other_data.len();
        assert_eq!(tsig.byte_size(), expected_len);
        assert_eq!(tsig.byte_size(), tsig.to_bytes().len());

        assert_eq!(
            tsig.to_bytes(),
            vec![
                8, 72, 77, 65, 67, 45, 77, 68, 53, 7, 83, 73, 71, 45, 65, 76, 71, 3, 82, 69, 71, 3,
                73, 78, 84, 0, 0, 0, 102, 79, 162, 15, 0, 15, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                0, 1, 0, 0, 0, 3, 11, 22, 33,
            ]
        );
    }
}
