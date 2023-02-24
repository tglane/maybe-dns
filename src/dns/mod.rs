mod byteconvertible;
mod error;
mod fqdn;
mod header;
mod packet;
mod question;
mod resource;
mod util;

const COMPRESSION_MASK: u8 = 0b1100_0000;
const COMPRESSION_MASK_U16: u16 = 0b1100_0000_0000_0000;

/// Submodule containing a dns packet
pub use self::packet::Packet;

/// Submodule containing dns question record type and enums for its dns class and dns type
pub use self::question::{QClass, QType, Question};

/// Submodule containing dns resource record type and enums for its dns class and dns type
pub use self::resource::{RecordClass, RecordData, RecordType, ResourceRecord};

/// Submodule containing fully qualified domain name (FQDN) type
pub use self::fqdn::FQDN;

/// Submodule containing dns packets header type and enums used in the header
pub use self::header::{Header, OpCode};

/// Submodule containing the error type used by this module to represent errors in a consistent way
pub use self::error::DnsError;

/// Submodule containing a trait for (de-)serializing DNS modules
pub use self::byteconvertible::ByteConvertible;

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn parse_simple_packet() {
        let bytes = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
        let packet = Packet::try_from(&bytes[..]);
        assert!(packet.is_ok());
    }

    #[test]
    fn build_query_correct() {
        let mut query = Packet::new();
        query.questions.push(Question::new(
            FQDN::new("_srv._udp.local"),
            QType::TXT,
            QClass::IN,
        ));
        query.questions.push(Question::new(
            FQDN::new("_srv2._udp.local"),
            QType::TXT,
            QClass::IN,
        ));

        let query = query.to_bytes();

        let parsed = Packet::try_from(&query[..]);
        assert!(parsed.is_ok());

        let parsed = parsed.unwrap();
        assert_eq!(2, parsed.questions.len());
        assert_eq!("_srv._udp.local", parsed.questions[0].q_name.to_string());
        assert_eq!("_srv2._udp.local", parsed.questions[1].q_name.to_string());
    }

    #[test]
    fn query_google_com() {
        let bytes = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
        let packet = Packet::try_from(&bytes[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();
        assert_eq!(1, packet.questions.len());
        assert_eq!("google.com", packet.questions[0].q_name.to_string());
        assert_eq!(QType::A, packet.questions[0].q_type);
        assert_eq!(QClass::IN, packet.questions[0].q_class);
    }

    #[test]
    fn reply_google_com() {
        let bytes = b"\x00\x03\x81\x80\x00\x01\x00\x0b\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\
        \x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x23\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\
        \x00\x04\x4a\x7d\xec\x25\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x27\xc0\x0c\x00\x01\x00\x01\x00\x00\
        \x00\x04\x00\x04\x4a\x7d\xec\x20\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x28\xc0\x0c\x00\x01\x00\x01\
        \x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x21\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x29\xc0\x0c\x00\x01\
        \x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x22\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x24\xc0\x0c\
        \x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x2e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x26";

        let packet = Packet::try_from(&bytes[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();
        assert_eq!(1, packet.questions.len());
        assert_eq!(11, packet.answers.len());

        assert_eq!("google.com", packet.answers[0].a_name.to_string());
        assert_eq!(RecordClass::IN, packet.answers[0].a_class);
        assert_eq!(4, packet.answers[0].time_to_live);
        assert_eq!(4, packet.answers[0].rdata.byte_size());

        match &packet.answers[0].rdata {
            RecordData::A(address) => {
                assert_eq!(1249766435, u32::from(*address));
            }
            _ => panic!("invalid RDATA"),
        }
    }
}
