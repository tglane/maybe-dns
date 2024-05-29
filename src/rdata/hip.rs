use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::fqdn::FQDN;
use crate::rdata::{Algorithm, RData, RecordData, RecordType};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hip {
    /// The PK algorithm field indicates the PK cryptographic algorithm and
    /// the implied Public Key field format.
    pub public_key_algorithm: Algorithm,

    /// The HIT is stored as a binary value in network byte order.
    pub hit: Vec<u8>,

    /// Public key in the format specified in `public_key_algorithm`
    pub public_key: Vec<u8>,

    /// The Rendezvous Server field indicates one or more variable length
    /// wire-encoded domain names of one or more RVSs, concatenated and
    /// encoded as described in Section 3.3 of RFC 1035 [RFC1035]:
    /// "<domain-name> is a domain name represented as a series of labels,
    /// and terminated by a label with zero length".  Since the wire-encoded
    /// format is self-describing, the length of each domain name is
    /// implicit: The zero length label termination serves as a separator
    /// between multiple RVS domain names concatenated in the Rendezvous
    /// Server field of a same HIP RR.  Since the length of the other portion
    /// of the RR's RRDATA is known, and the overall length of the RR's RDATA
    /// is also known (RDLENGTH), all the length information necessary to
    /// parse the HIP RR is available.
    pub rendevous_server: Option<Vec<FQDN>>,
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Hip {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let hit_len = buffer.extract_u8()?;
        let public_key_algorithm = buffer.extract_u8()?.try_into()?;
        let pk_len = buffer.extract_u16()?;

        let hit = buffer.extract_bytes(hit_len as usize)?.to_vec();
        let public_key = buffer.extract_bytes(pk_len as usize)?.to_vec();
        let rendevous_server = if buffer.remaining() > 0 {
            let mut names = Vec::default();
            while buffer.remaining() > 0 {
                names.push(buffer.extract_fqdn()?);
            }
            Some(names)
        } else {
            None
        };

        Ok(Self {
            public_key_algorithm,
            hit,
            public_key,
            rendevous_server,
        })
    }
}

impl RData for Hip {
    fn record_type(&self) -> RecordType {
        RecordType::HIP
    }

    fn into_record_data(self) -> RecordData {
        RecordData::HIP(self)
    }
}

impl ByteConvertible for Hip {
    fn byte_size(&self) -> usize {
        4 + self.hit.len()
            + self.public_key.len()
            + self
                .rendevous_server
                .as_ref()
                .map(|b| -> usize { b.iter().map(|fqdn| fqdn.byte_size()).sum() })
                .unwrap_or_default()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.push(self.hit.len() as u8);
        buf.push(self.public_key_algorithm.into());
        buf.extend(u16::to_be_bytes(self.public_key.len() as u16));
        buf.extend(&self.hit);
        buf.extend(&self.public_key);
        if let Some(rs) = &self.rendevous_server {
            for name in rs {
                buf.extend(name.to_bytes());
            }
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let hit = [
            0x20, 0x01, 0x00, 0x10, 0x7B, 0x1A, 0x74, 0xDF, 0x36, 0x56, 0x39, 0xCC, 0x39, 0xF1,
            0xD5, 0x78,
        ];
        let pk = b"AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D".to_vec();
        let mut data = vec![hit.len() as u8, 2];
        data.extend(u16::to_be_bytes(pk.len() as u16));
        data.extend(hit);
        data.extend(&pk);
        data.extend(FQDN::new("rvs1.example.com.").to_bytes());

        let hip = Hip::try_from(&mut DnsBuffer::from(data.as_slice())).unwrap();

        assert_eq!(hip.public_key_algorithm, Algorithm::DSA);
        assert_eq!(hip.hit, hit);
        assert_eq!(hip.public_key, pk);
        assert_eq!(
            hip.rendevous_server,
            Some(vec![FQDN::new("rvs1.example.com.")])
        );

        assert_eq!(hip.byte_size(), data.len());
        assert_eq!(hip.to_bytes(), data);
    }

    #[test]
    fn build() {
        let hip = Hip {
            public_key_algorithm: Algorithm::DSA,
            hit: vec![
                0x20, 0x01, 0x00, 0x10, 0x7B, 0x1A, 0x74, 0xDF, 0x36, 0x56, 0x39, 0xCC, 0x39, 0xF1,
                0xD5, 0x78,
            ],
            public_key: b"AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D".to_vec(),
            rendevous_server: Some(vec![
                FQDN::new("rvs1.example.com."),
                FQDN::new("rvs2.example.com."),
            ]),
        };

        let hit_len = hip.hit.len() as u8;
        let pk_algo = hip.public_key_algorithm as u8;
        let pk_len = u16::to_be_bytes(hip.public_key.len() as u16);
        assert_eq!(
            hip.to_bytes(),
            vec![
                hit_len, pk_algo, pk_len[0], pk_len[1], 32, 1, 0, 16, 123, 26, 116, 223, 54, 86,
                57, 204, 57, 241, 213, 120, 65, 119, 69, 65, 65, 98, 100, 120, 121, 104, 78, 117,
                83, 117, 116, 99, 53, 69, 77, 122, 120, 84, 115, 57, 76, 66, 80, 67, 73, 107, 79,
                70, 72, 56, 99, 73, 118, 77, 52, 112, 57, 43, 76, 114, 86, 52, 101, 49, 57, 87,
                122, 75, 48, 48, 43, 67, 73, 54, 122, 66, 67, 81, 84, 100, 116, 87, 115, 117, 120,
                75, 98, 87, 73, 121, 56, 55, 85, 79, 111, 74, 84, 119, 107, 85, 115, 55, 108, 66,
                117, 43, 85, 112, 114, 49, 103, 115, 78, 114, 117, 116, 55, 57, 114, 121, 114, 97,
                43, 98, 83, 82, 71, 81, 98, 49, 115, 108, 73, 109, 65, 56, 89, 86, 74, 121, 117,
                73, 68, 115, 106, 55, 107, 119, 122, 71, 55, 106, 110, 69, 82, 78, 113, 110, 87,
                120, 90, 52, 56, 65, 87, 107, 115, 107, 109, 100, 72, 97, 86, 68, 80, 52, 66, 99,
                101, 108, 114, 84, 73, 51, 114, 77, 88, 100, 88, 70, 53, 68, 4, 114, 118, 115, 49,
                7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 4, 114, 118, 115, 50, 7,
                101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0
            ]
        );
    }
}
