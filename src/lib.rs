mod buffer;
mod byteconvertible;
mod error;
mod fqdn;
mod header;
mod packet;
mod question;
mod record_data;
mod resource;
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

/// Submodule containing dns record data type used as a payload in a DNS resource
pub use self::record_data::RecordData;

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

    const GOOGLE_QUERY_SAMPLE: &[u8; 28] =
        b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

    const GOOGLE_REPLY_SAMPLE_ONE: &[u8; 204] = b"\x00\x03\x81\x80\x00\x01\x00\x0b\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\
        \x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x23\xc0\
        \x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x25\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\
        \x4a\x7d\xec\x27\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x20\xc0\x0c\x00\x01\x00\x01\x00\
        \x00\x00\x04\x00\x04\x4a\x7d\xec\x28\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x21\xc0\x0c\
        \x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x29\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\
        \x7d\xec\x22\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x24\xc0\x0c\x00\x01\x00\x01\x00\x00\
        \x00\x04\x00\x04\x4a\x7d\xec\x2e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x26";

    const GOOGLE_REPLY_SAMPLE_TWO: &[u8; 116] = b"\xd5\xad\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x03www\x06google\x03com\
        \x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x05\x00\x08\x03www\x01l\xc0\x10\xc0,\x00\x01\x00\x01\
        \x00\x00\x00\x05\x00\x04B\xf9[h\xc0,\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04B\xf9[c\xc0,\x00\x01\x00\x01\x00\
        \x00\x00\x05\x00\x04B\xf9[g\xc0,\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04B\xf9[\x93";

    #[test]
    fn parse_query_from_github() {
        let packet = Packet::try_from(&GOOGLE_REPLY_SAMPLE_TWO[..]);
        println!("{:?}", packet);
        assert!(packet.is_ok());
    }

    #[test]
    fn parse_simple_query_packet() {
        let packet = Packet::try_from(&GOOGLE_QUERY_SAMPLE[..]);
        println!("{:?}", packet.unwrap());
        // assert!(packet.is_ok());
    }

    #[test]
    fn fqdn_link_local() {
        let local = FQDN::new("_airplay._tcp.local");
        let non_local = FQDN::new("google.com");

        assert_eq!(local.is_link_local(), true);
        assert_eq!(non_local.is_link_local(), false);
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
        println!("{:?}", packet);
        assert_eq!(1, packet.questions().len());
        assert_eq!("google.com", packet.questions()[0].q_name.to_string());
        assert_eq!(QType::A, packet.questions()[0].q_type);
        assert_eq!(QClass::IN, packet.questions()[0].q_class);
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

        let parsed_comp = Packet::try_from(&GOOGLE_REPLY_SAMPLE_TWO[..]).unwrap();
        println!(
            "My: {:?}\nOther: {:?}",
            reply.header(),
            parsed_comp.header() // &GOOGLE_REPLY_SAMPLE_TWO[..10]
        );

        // Test if compression works
        assert_eq!(reply.to_bytes_compressed(), GOOGLE_REPLY_SAMPLE_TWO);
    }
}
