mod buffer;
mod byteconvertible;
mod error;
mod fqdn;
mod header;
mod packet;
mod question;
mod rdata;
mod resource;
mod resource_record_set;
mod util;

const COMPRESSION_MASK: u8 = 0b1100_0000;
const COMPRESSION_MASK_U16: u16 = 0b1100_0000_0000_0000;

/// Simple abstraction over a non-owning binary buffer containing methods to extract DNS data types
pub use self::buffer::DnsBuffer;

/// Submodule containing a dns packet
pub use self::packet::Packet;

/// Submodule containing dns question record type and enums for its dns class and dns type
pub use self::question::{QClass, QType, Question};

/// Submodule containing dns resource record type and enums for its dns class and dns type
pub use self::resource::{RecordClass, RecordType, ResourceRecord};

/// Submodule containing the representation of a non-owning resource record set
pub use self::resource_record_set::ResourceRecordSet;

/// Submodule containing all RDATA structures that are specified for DNS and used as payload types
pub use self::rdata::{RecordData, DNSKEY, DS, NSEC, RRSIG};

/// Submodule containing fully qualified domain name (FQDN) type
pub use self::fqdn::FQDN;

/// Submodule containing dns packets header type and enums used in the header
pub use self::header::{Header, OpCode, ResponseCode};

/// Submodule containing the error type used by this module to represent errors in a consistent way
pub use self::error::DnsError;

/// Submodule containing a trait for (de-)serializing DNS modules
pub use self::byteconvertible::ByteConvertible;

#[cfg(test)]
mod tests {
    use std::{convert::TryFrom, net::Ipv4Addr, str::FromStr};

    use super::*;

    const GOOGLE_QUERY_SAMPLE: &[u8; 28] = b"\x00\x03\
        \x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\
        \x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

    const GOOGLE_REPLY_SAMPLE_ONE: &[u8; 204] = b"\x00\x03\x81\x80\x00\
        \x01\x00\x0b\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\
        \x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x23\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x25\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x27\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x20\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x28\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x21\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x29\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x22\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x24\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x2e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\
        \x04\x00\x04\x4a\x7d\xec\x26";

    const GOOGLE_REPLY_SAMPLE_TWO: &[u8; 116] = b"\xd5\xad\x81\x80\x00\
        \x01\x00\x05\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\
        \x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x05\x00\x08\x03www\
        \x01l\xc0\x10\xc0,\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04B\xf9[h\
        \xc0,\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04B\xf9[c\xc0,\x00\x01\
        \x00\x01\x00\x00\x00\x05\x00\x04B\xf9[g\xc0,\x00\x01\x00\x01\x00\
        \x00\x00\x05\x00\x04B\xf9[\x93";

    #[cfg(feature = "mdns")]
    const IPHONE_MDNS_QUERY_RESPONSE: &[u8; 649] = b"\x00\x00\
        \x84\x00\x00\x00\x00\x0b\x00\x00\x00\x06\x0f\x69\x50\x68\x6f\x6e\
        \x65\x20\x76\x6f\x6e\x20\x54\x69\x6d\x6f\x07\x5f\x72\x64\x6c\x69\
        \x6e\x6b\x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x10\
        \x80\x01\x00\x00\x11\x94\x00\x35\x16\x72\x70\x42\x41\x3d\x31\x37\
        \x3a\x35\x41\x3a\x34\x31\x3a\x30\x46\x3a\x38\x46\x3a\x39\x39\x0b\
        \x72\x70\x56\x72\x3d\x34\x34\x30\x2e\x31\x30\x11\x72\x70\x41\x44\
        \x3d\x64\x36\x32\x31\x61\x32\x37\x31\x33\x62\x62\x37\x09\x5f\x73\
        \x65\x72\x76\x69\x63\x65\x73\x07\x5f\x64\x6e\x73\x2d\x73\x64\x04\
        \x5f\x75\x64\x70\xc0\x29\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x02\
        \xc0\x1c\xc0\x1c\x00\x0c\x00\x01\x00\x00\x11\x94\x00\x02\xc0\x0c\
        \x0f\x69\x50\x68\x6f\x6e\x65\x20\x76\x6f\x6e\x20\x54\x69\x6d\x6f\
        \x0c\x5f\x64\x65\x76\x69\x63\x65\x2d\x69\x6e\x66\x6f\xc0\x24\x00\
        \x10\x00\x01\x00\x00\x11\x94\x00\x0d\x0c\x6d\x6f\x64\x65\x6c\x3d\
        \x4e\x38\x34\x31\x41\x50\xc0\x0c\x00\x21\x80\x01\x00\x00\x00\x78\
        \x00\x18\x00\x00\x00\x00\xc0\x04\x0f\x69\x50\x68\x6f\x6e\x65\x2d\
        \x76\x6f\x6e\x2d\x54\x69\x6d\x6f\xc0\x29\x01\x33\x01\x46\x01\x38\
        \x01\x30\x01\x42\x01\x45\x01\x31\x01\x45\x01\x34\x01\x38\x01\x33\
        \x01\x35\x01\x33\x01\x35\x01\x34\x01\x31\x01\x30\x01\x30\x01\x30\
        \x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\x01\x30\
        \x01\x30\x01\x30\x01\x38\x01\x45\x01\x46\x03\x69\x70\x36\x04\x61\
        \x72\x70\x61\x00\x00\x0c\x80\x01\x00\x00\x00\x78\x00\x02\xc0\xea\
        \x02\x32\x31\x03\x31\x37\x38\x03\x31\x36\x38\x03\x31\x39\x32\x07\
        \x69\x6e\x2d\x61\x64\x64\x72\xc1\x40\x00\x0c\x80\x01\x00\x00\x00\
        \x78\x00\x02\xc0\xea\x01\x31\x01\x36\x01\x35\x01\x44\x01\x33\x01\
        \x37\x01\x32\x01\x46\x01\x43\x01\x39\x01\x31\x01\x30\x01\x37\x01\
        \x34\x01\x34\x01\x31\x01\x30\x01\x42\x01\x44\x01\x33\x01\x30\x01\
        \x34\x01\x34\x01\x32\x01\x39\x01\x30\x01\x31\x01\x38\x01\x32\x01\
        \x30\x01\x41\x01\x32\xc1\x3c\x00\x0c\x80\x01\x00\x00\x00\x78\x00\
        \x02\xc0\xea\xc0\xea\x00\x1c\x80\x01\x00\x00\x00\x78\x00\x10\xfe\
        \x80\x00\x00\x00\x00\x00\x00\x14\x53\x53\x84\xe1\xeb\x08\xf3\xc0\
        \xea\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\xa8\xb2\x15\xc0\
        \xea\x00\x1c\x80\x01\x00\x00\x00\x78\x00\x10\x2a\x02\x81\x09\x24\
        \x40\x3d\xb0\x14\x47\x01\x9c\xf2\x73\xd5\x61\xc0\x0c\x00\x2f\x80\
        \x01\x00\x00\x11\x94\x00\x09\xc0\x0c\x00\x05\x00\x00\x80\x00\x40\
        \xc0\xfc\x00\x2f\x80\x01\x00\x00\x00\x78\x00\x06\xc0\xfc\x00\x02\
        \x00\x08\xc1\x52\x00\x2f\x80\x01\x00\x00\x00\x78\x00\x06\xc1\x52\
        \x00\x02\x00\x08\xc1\x77\x00\x2f\x80\x01\x00\x00\x00\x78\x00\x06\
        \xc1\x77\x00\x02\x00\x08\xc0\xea\x00\x2f\x80\x01\x00\x00\x00\x78\
        \x00\x08\xc0\xea\x00\x04\x40\x00\x00\x08\x00\x00\x29\x05\xa0\x00\
        \x00\x11\x94\x00\x12\x00\x04\x00\x0e\x00\x0e\xf6\xaf\xe7\x8a\xaa\
        \xe6\xee\xb0\xca\x90\xe4\xe3";

    #[cfg(feature = "mdns")]
    const MYSTERY: &[u8; 387] = b"\x00\x00\
        \x00\x00\x00\x05\x00\x00\x00\x07\x00\x01\x0f\x57\x6f\x68\x6e\xc2\
        \xad\x7a\x69\x6d\x6d\x65\x72\x20\x54\x56\x0f\x5f\x63\x6f\x6d\x70\
        \x61\x6e\x69\x6f\x6e\x2d\x6c\x69\x6e\x6b\x04\x5f\x74\x63\x70\x05\
        \x6c\x6f\x63\x61\x6c\x00\x00\xff\x00\x01\x0f\x57\x6f\x68\x6e\xc2\
        \xad\x7a\x69\x6d\x6d\x65\x72\x20\x54\x56\x08\x5f\x61\x69\x72\x70\
        \x6c\x61\x79\xc0\x2c\x00\xff\x00\x01\x1c\x34\x30\x43\x42\x43\x30\
        \x43\x44\x34\x31\x36\x44\x40\x57\x6f\x68\x6e\xc2\xad\x7a\x69\x6d\
        \x6d\x65\x72\x20\x54\x56\x05\x5f\x72\x61\x6f\x70\xc0\x2c\x00\xff\
        \x00\x01\x1d\x37\x30\x2d\x33\x35\x2d\x36\x30\x2d\x36\x33\x2e\x31\
        \x20\x57\x6f\x68\x6e\xc2\xad\x7a\x69\x6d\x6d\x65\x72\x20\x54\x56\
        \x0c\x5f\x73\x6c\x65\x65\x70\x2d\x70\x72\x6f\x78\x79\x04\x5f\x75\
        \x64\x70\xc0\x31\x00\xff\x00\x01\x0d\x57\x6f\x68\x6e\x7a\x69\x6d\
        \x6d\x65\x72\x2d\x54\x56\xc0\x31\x00\xff\x80\x01\xc0\x0c\x00\x21\
        \x00\x01\x00\x00\x00\x78\x00\x08\x00\x00\x00\x00\xc0\x01\xc0\xba\
        \xc0\x3c\x00\x21\x00\x01\x00\x00\x00\x78\x00\x08\x00\x00\x00\x00\
        \x1b\x58\xc0\xba\xc0\x5b\x00\x21\x00\x01\x00\x00\x00\x78\x00\x08\
        \x00\x00\x00\x00\x1b\x58\xc0\xba\xc0\x84\x00\x21\x00\x01\x00\x00\
        \x00\x78\x00\x08\x00\x00\x00\x00\xe0\x2b\xc0\xba\xc0\xba\x00\x1c\
        \x00\x01\x00\x00\x00\x78\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00\
        \x1c\x80\x9e\xa3\x63\x00\xc6\x63\xc0\xba\x00\x1c\x00\x01\x00\x00\
        \x00\x78\x00\x10\x2a\x02\x81\x09\x24\x40\x3d\xb0\x18\x8d\x8e\x59\
        \xc8\x7d\xe5\x77\xc0\xba\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\
        \xc0\xa8\xb2\x20\x00\x00\x29\x05\xa0\x00\x00\x11\x94\x00\x12\x00\
        \x04\x00\x0e\x00\xba\x40\xcb\xc0\xcd\x41\x6d\x40\xcb\xc0\xcd\x41\
        \x6b";

    #[cfg(feature = "mdns")]
    const MDNS_INCLUDING_NSEC: &[u8; 211] = b"\x00\x00\x84\x00\x00\x00\
        \x00\x01\x00\x00\x00\x01\x09\x50\x69\x65\x74\x20\xf0\x9f\xab\xa8\
        \x0f\x5f\x63\x6f\x6d\x70\x61\x6e\x69\x6f\x6e\x2d\x6c\x69\x6e\x6b\
        \x04\x5f\x74\x63\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x10\x80\x01\
        \x00\x00\x11\x94\x00\x82\x07\x72\x70\x4d\x61\x63\x3d\x30\x11\x72\
        \x70\x48\x4e\x3d\x65\x61\x33\x64\x33\x64\x39\x64\x38\x63\x32\x62\
        \x0c\x72\x70\x46\x6c\x3d\x30\x78\x33\x30\x30\x30\x30\x11\x72\x70\
        \x48\x41\x3d\x64\x33\x38\x62\x61\x37\x38\x63\x66\x34\x61\x36\x0d\
        \x72\x70\x56\x72\x3d\x35\x30\x30\x2e\x36\x30\x2e\x34\x11\x72\x70\
        \x41\x44\x3d\x37\x65\x39\x62\x33\x35\x34\x31\x34\x38\x38\x37\x11\
        \x72\x70\x48\x49\x3d\x39\x36\x39\x65\x30\x61\x30\x33\x35\x35\x34\
        \x33\x16\x72\x70\x42\x41\x3d\x30\x44\x3a\x34\x39\x3a\x30\x38\x3a\
        \x43\x42\x3a\x34\x31\x3a\x35\x44\xc0\x0c\x00\x2f\x80\x01\x00\x00\
        \x11\x94\x00\x09\xc0\x0c\x00\x05\x00\x00\x80\x00\x40";

    #[test]
    fn parse_query_from_github() {
        let packet = Packet::try_from(&GOOGLE_REPLY_SAMPLE_TWO[..]);
        assert!(packet.is_ok());
    }

    #[test]
    fn parse_simple_query_packet() {
        let packet = Packet::try_from(&GOOGLE_QUERY_SAMPLE[..]);
        assert!(packet.is_ok());
    }

    #[test]
    fn build_query_correct() {
        let mut query = Packet::new();
        query.add_question(Question::new(
            FQDN::new("_srv._udp.local"),
            QType::TXT,
            QClass::IN,
        ));
        query.add_question(Question::new(
            FQDN::from(&["_srv2", "_udp", "local"][..]),
            QType::TXT,
            QClass::IN,
        ));

        let query = query.to_bytes();

        let parsed = Packet::try_from(&query[..]);
        assert!(parsed.is_ok());

        let parsed = parsed.unwrap();
        assert_eq!(2, parsed.questions().len());
        assert_eq!("_srv._udp.local", parsed.questions()[0].q_name.to_string());
        assert_eq!("_srv2._udp.local", parsed.questions()[1].q_name.to_string());
    }

    #[test]
    fn parse_query_google_com() {
        let packet = Packet::try_from(&GOOGLE_QUERY_SAMPLE[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();
        assert_eq!(1, packet.questions().len());
        assert_eq!("google.com", packet.questions()[0].q_name.to_string());
        assert_eq!(QType::A, packet.questions()[0].q_type);
        assert_eq!(QClass::IN, packet.questions()[0].q_class);

        assert_eq!(packet.to_bytes_compressed(), GOOGLE_QUERY_SAMPLE);
    }

    #[test]
    fn build_query_google_com() {
        let query = Packet::with_questions(
            3,
            true,
            vec![Question::new(FQDN::new("google.com"), QType::A, QClass::IN)],
        );

        assert_eq!(1, query.questions().len());
        assert_eq!("google.com", query.questions()[0].q_name.to_string());
        assert_eq!(QType::A, query.questions()[0].q_type);
        assert_eq!(QClass::IN, query.questions()[0].q_class);

        let query_bytes = query.to_bytes();
        assert_eq!(query_bytes, GOOGLE_QUERY_SAMPLE);
    }

    #[test]
    fn parse_reply_google_com() {
        let packet = Packet::try_from(&GOOGLE_REPLY_SAMPLE_ONE[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();
        assert_eq!(1, packet.questions().len());
        assert_eq!(11, packet.answers().len());

        for answer in packet.answers().iter() {
            assert_eq!("google.com", answer.a_name.to_string());
            assert_eq!(answer.a_type, RecordType::A);
            assert_eq!(answer.a_class, RecordClass::IN);
            assert_eq!(answer.time_to_live(), 4);
            assert_eq!(answer.rdata.byte_size(), 4);
            assert!(matches!(answer.rdata, RecordData::A(_)));
        }

        assert_eq!("google.com", packet.answers()[0].a_name.to_string());
        assert_eq!(RecordClass::IN, packet.answers()[0].a_class);
        assert_eq!(4, packet.answers()[0].time_to_live);
        assert_eq!(4, packet.answers()[0].rdata.byte_size());

        match &packet.answers()[0].rdata {
            RecordData::A(address) => {
                assert_eq!(1249766435, u32::from(*address));
            }
            _ => panic!("invalid RDATA"),
        }

        assert_eq!(packet.to_bytes_compressed(), GOOGLE_REPLY_SAMPLE_ONE);
    }

    #[test]
    fn parst_complex_reply_google_com() {
        let packet = Packet::try_from(&GOOGLE_REPLY_SAMPLE_TWO[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();

        assert_eq!(0xD5AD, packet.id());
        assert_eq!(OpCode::StandardQuery, packet.opcode());
        assert_eq!(true, packet.recursion_desired());
        assert_eq!(true, packet.recursion_available());
        assert_eq!(ResponseCode::NoError, packet.response_code());
        assert_eq!(true, packet.query_response());
        assert_eq!(false, packet.authoritative_answer());

        assert_eq!(1, packet.questions().len());
        assert_eq!(5, packet.answers().len());

        let question = &packet.questions()[0];
        assert_eq!(&QClass::IN, question.class());
        assert_eq!(&QType::A, question.query_type());
        assert_eq!(&FQDN::new("www.google.com"), question.name());

        let first_record = &packet.answers()[0];
        assert_eq!("www.google.com", first_record.a_name.to_string());
        assert_eq!(first_record.a_type, RecordType::CNAME);
        assert_eq!(first_record.a_class, RecordClass::IN);
        assert_eq!(first_record.time_to_live(), 5);
        assert_eq!(first_record.rdata.byte_size(), 18);
        assert_eq!(first_record.rdata.to_bytes().len(), 18);
        assert_eq!(
            vec![3, 119, 119, 119, 1, 108, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0],
            first_record.rdata.to_bytes()
        );
        assert_eq!(
            first_record.rdata,
            RecordData::CNAME(FQDN::new("www.l.google.com"))
        );

        for idx in 1..packet.answers().len() {
            let ans_ref = &packet.answers()[idx];

            assert_eq!("www.l.google.com", ans_ref.a_name.to_string());
            assert_eq!(ans_ref.a_type, RecordType::A);
            assert_eq!(ans_ref.a_class, RecordClass::IN);
            assert_eq!(ans_ref.time_to_live(), 5);
            assert_eq!(ans_ref.rdata.byte_size(), 4);
            assert!(matches!(ans_ref.rdata, RecordData::A(_)));
        }

        assert_eq!(packet.to_bytes_compressed(), GOOGLE_REPLY_SAMPLE_TWO);
    }

    #[test]
    fn build_complex_reply_google_com() {
        let mut reply = Packet::new_reply(3);

        let mut header = Header::new();
        header.id = 0xD5AD;
        header.set_opcode(OpCode::StandardQuery);
        header.set_response_code(ResponseCode::NoError);
        header.set_recursion_available(true);
        header.set_recursion_desired(true);
        header.set_query_response(true);
        header.set_authoritative_answer(false);

        reply.set_header(header);

        reply.add_question(Question::new(
            FQDN::from("www.google.com"),
            QType::A,
            QClass::IN,
        ));

        reply.add_answer(ResourceRecord::new(
            FQDN::from("www.google.com"),
            RecordType::CNAME,
            RecordClass::IN,
            5,
            RecordData::CNAME(FQDN::from("www.l.google.com")),
        ));

        reply.add_answer(ResourceRecord::new(
            FQDN::from("www.l.google.com"),
            RecordType::A,
            RecordClass::IN,
            5,
            RecordData::A(Ipv4Addr::from_str("66.249.91.104").unwrap()),
        ));

        reply.add_answer(ResourceRecord::new(
            FQDN::from("www.l.google.com"),
            RecordType::A,
            RecordClass::IN,
            5,
            RecordData::A(Ipv4Addr::from_str("66.249.91.99").unwrap()),
        ));

        reply.add_answer(ResourceRecord::new(
            FQDN::from("www.l.google.com"),
            RecordType::A,
            RecordClass::IN,
            5,
            RecordData::A(Ipv4Addr::from_str("66.249.91.103").unwrap()),
        ));

        reply.add_answer(ResourceRecord::new(
            FQDN::from("www.l.google.com"),
            RecordType::A,
            RecordClass::IN,
            5,
            RecordData::A(Ipv4Addr::from_str("66.249.91.147").unwrap()),
        ));

        // Test if compression works
        assert_eq!(reply.to_bytes_compressed(), GOOGLE_REPLY_SAMPLE_TWO);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn parse_mystery() {
        let packet = Packet::try_from(&MYSTERY[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();

        let header = packet.header();
        assert_eq!(header.ques_count, 5);
        assert_eq!(header.ans_count, 0);
        assert_eq!(header.auth_count, 7);
        assert_eq!(header.add_count, 1);

        assert_eq!(packet.questions().len(), 5);
        assert_eq!(packet.answers().len(), 0);
        assert_eq!(packet.authorities().len(), 7);
        assert_eq!(packet.additionals().len(), 1);

        assert_eq!(&packet.to_bytes_compressed(), MYSTERY);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn parse_iphone_mds_query_response() {
        let packet = Packet::try_from(&IPHONE_MDNS_QUERY_RESPONSE[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();

        let header = packet.header();
        assert_eq!(header.ques_count, 0);
        assert_eq!(header.ans_count, 11);
        assert_eq!(header.auth_count, 0);
        assert_eq!(header.add_count, 6);

        assert_eq!(packet.questions().len(), 0);
        assert_eq!(packet.answers().len(), 11);
        assert_eq!(packet.authorities().len(), 0);
        assert_eq!(packet.additionals().len(), 6);

        assert_eq!(&packet.to_bytes_compressed(), IPHONE_MDNS_QUERY_RESPONSE);
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn parse_something_with_nsec() {
        use crate::{RecordClass::*, RecordType::*};

        let packet = Packet::try_from(&MDNS_INCLUDING_NSEC[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();
        assert_eq!(
            packet.header().opcode(),
            crate::header::OpCode::StandardQuery
        );
        assert_eq!(packet.questions().len(), 0);
        assert_eq!(packet.answers().len(), 1);
        assert_eq!(packet.authorities().len(), 0);
        assert_eq!(packet.additionals().len(), 1);

        let answer = &packet.answers()[0];
        assert_eq!(answer.a_type, TXT);
        assert_eq!(answer.a_class, IN);
        assert_eq!(
            answer.a_name.to_string(),
            "Piet 🫨._companion-link._tcp.local"
        );

        let add = &packet.additionals()[0];
        assert_eq!(add.a_type, NSEC);
        assert_eq!(add.a_class, IN);
        assert_eq!(add.a_name.to_string(), "Piet 🫨._companion-link._tcp.local");

        assert_eq!(packet.to_bytes_compressed(), MDNS_INCLUDING_NSEC);
    }

    // #[cfg(feature = "mdns")]
    // #[test]
    // fn network_test() {
    //     use crate::*;
    //     use std::net::UdpSocket;

    //     let sock = UdpSocket::bind("0.0.0.0:0").expect("Could not create socket");
    //     sock.set_multicast_loop_v4(true).unwrap();

    //     let mut packet = Packet::new_query(0, false);
    //     packet.add_question(Question::new(
    //         "_googlecast._tcp.local".into(),
    //         QType::PTR,
    //         QClass::IN,
    //     ));

    //     sock.send_to(&packet.to_bytes(), "224.0.0.251:5353")
    //         .expect("Could not send data");

    //     let mut buf = [0_u8; 1024];
    //     let (bytes_recv, _) = sock.recv_from(&mut buf).expect("");

    //     let response = Packet::try_from(&buf[..bytes_recv]).expect("Failed to parse mDNS response");

    //     println!("Res: {:?}", response);
    //     assert!(false);
    // }
}
