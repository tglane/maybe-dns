use std::convert::{TryFrom, TryInto};

use super::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use super::error::DnsError;
use super::fqdn::FQDN;
use super::header::{Header, OpCode, ResponseCode};
use super::question::{QClass, QType, Question};
use super::resource::{RecordClass, RecordData, RecordType, ResourceRecord};
use super::util::{get_name_range, resolve_pointer_in_name};

#[derive(Clone, Debug, Default)]
pub struct Packet {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authorities: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>,
}

impl Packet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_query(id: u16, rc: bool) -> Self {
        Packet {
            header: Header::new_query(id, rc),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn new_reply(id: u16) -> Self {
        Self {
            header: Header::new_reply(id, OpCode::StandardQuery),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn with_questions(id: u16, rc: bool, questions: Vec<Question>) -> Self {
        Packet {
            header: Header::new_query(id, rc),
            questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn id(&self) -> u16 {
        self.header.id
    }

    pub fn set_id(&mut self, id: u16) {
        self.header.id = id;
    }

    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired()
    }

    pub fn set_recursion_desired(&mut self, rd: bool) {
        self.header.set_recursion_desired(rd);
    }

    pub fn truncation(&self) -> bool {
        self.header.truncation()
    }

    pub fn set_truncation(&mut self, truncation: bool) {
        // TODO Reset vecs of packet to truncate it?
        self.header.set_truncation(truncation);
    }

    pub fn authoritative_answer(&self) -> bool {
        self.header.authoritative_answer()
    }

    pub fn set_authoritative_answer(&mut self, aa: bool) {
        self.header.set_authoritative_answer(aa);
    }

    pub fn opcode(&self) -> OpCode {
        self.header.opcode()
    }

    pub fn set_opcode(&mut self, op_code: OpCode) {
        self.header.set_opcode(op_code);
    }

    pub fn query_response(&self) -> bool {
        self.header.query_response()
    }

    pub fn set_query_response(&mut self, qr: bool) {
        self.header.set_query_response(qr);
    }

    pub fn response_code(&self) -> ResponseCode {
        self.header.response_code()
    }

    pub fn set_response_code(&mut self, response_code: ResponseCode) {
        self.header.set_response_code(response_code);
    }

    pub fn recursion_available(&self) -> bool {
        self.header.recursion_available()
    }

    pub fn set_recursion_available(&mut self, ra: bool) {
        self.header.set_recursion_available(ra);
    }

    pub fn set_header(&mut self, header: Header) {
        self.header = header;

        self.header.ques_count = self.questions.len() as u16;
        self.header.ans_count = self.answers.len() as u16;
        self.header.auth_count = self.authorities.len() as u16;
        self.header.add_count = self.additional.len() as u16;
    }

    pub fn questions(&self) -> &[Question] {
        &self.questions
    }

    pub fn take_questions(&mut self) -> Vec<Question> {
        self.header.ques_count = 0;
        std::mem::take(&mut self.questions)
    }

    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.ques_count += 1;
    }

    pub fn set_questions(&mut self, questions: Vec<Question>) {
        self.questions = questions;
        self.header.ques_count = self.questions.len() as u16;
    }

    pub fn answers(&self) -> &[ResourceRecord] {
        &self.answers
    }

    pub fn take_answers(&mut self) -> Vec<ResourceRecord> {
        self.header.ans_count = 0;
        std::mem::take(&mut self.answers)
    }

    pub fn add_answer(&mut self, answer: ResourceRecord) {
        self.answers.push(answer);
        self.header.ans_count += 1;
    }

    pub fn set_answers(&mut self, answers: Vec<ResourceRecord>) {
        self.answers = answers;
        self.header.ans_count = self.answers.len() as u16;
    }

    pub fn authorities(&self) -> &[ResourceRecord] {
        &self.authorities
    }

    pub fn take_authorities(&mut self) -> Vec<ResourceRecord> {
        self.header.ans_count = 0;
        std::mem::take(&mut self.authorities)
    }

    pub fn add_authority(&mut self, auth: ResourceRecord) {
        self.authorities.push(auth);
        self.header.auth_count += 1;
    }

    pub fn set_authorities(&mut self, authorities: Vec<ResourceRecord>) {
        self.authorities = authorities;
        self.header.auth_count = self.authorities.len() as u16;
    }

    pub fn additionals(&self) -> &[ResourceRecord] {
        &self.additional
    }

    pub fn take_additionals(&mut self) -> Vec<ResourceRecord> {
        self.header.add_count = 0;
        std::mem::take(&mut self.additional)
    }

    pub fn add_additional(&mut self, add: ResourceRecord) {
        self.additional.push(add);
        self.header.add_count += 1;
    }

    pub fn set_additionals(&mut self, additionals: Vec<ResourceRecord>) {
        self.additional = additionals;
        self.header.add_count = self.additional.len() as u16;
    }

    pub fn to_bytes_compressed(&self) -> Vec<u8> {
        let mut used_fqdn = std::collections::HashMap::<u64, usize>::new();

        let mut bin = self.header.to_bytes();

        for ques in self.questions.iter() {
            bin.extend_from_slice(&ques.to_bytes_compressed(&mut used_fqdn, bin.len()));
        }
        for rec in self.answers.iter() {
            bin.extend_from_slice(&rec.to_bytes_compressed(&mut used_fqdn, bin.len()));
        }
        for rec in self.authorities.iter() {
            bin.extend_from_slice(&rec.to_bytes_compressed(&mut used_fqdn, bin.len()));
        }
        for rec in self.additional.iter() {
            bin.extend_from_slice(&rec.to_bytes_compressed(&mut used_fqdn, bin.len()));
        }

        bin
    }
}

impl ByteConvertible for Packet {
    fn byte_size(&self) -> usize {
        let mut size = Header::SIZE;
        for ques in self.questions.iter() {
            size += ques.byte_size();
        }
        for rec in self.answers.iter() {
            size += rec.byte_size();
        }
        for rec in self.authorities.iter() {
            size += rec.byte_size();
        }
        for rec in self.additional.iter() {
            size += rec.byte_size();
        }
        size
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut byte_len = self.header.byte_size();
        for ques in self.questions.iter() {
            byte_len += ques.byte_size();
        }
        for rec in self.answers.iter() {
            byte_len += rec.byte_size();
        }
        for rec in self.authorities.iter() {
            byte_len += rec.byte_size();
        }
        for rec in self.additional.iter() {
            byte_len += rec.byte_size();
        }

        let mut bin = Vec::with_capacity(byte_len);
        bin.extend_from_slice(&self.header.to_bytes());

        // Set correct number of element into the header
        let mut ptr = bin.as_mut_ptr() as *mut u16;
        // Safe to dereference the pointer because the vector the pointer points to
        // was created with the expected capacity beforehand
        unsafe {
            ptr = ptr.offset(2);
            *ptr = (self.questions.len() as u16).to_be();
            ptr = ptr.offset(1);
            *ptr = (self.answers.len() as u16).to_be();
            ptr = ptr.offset(1);
            *ptr = (self.authorities.len() as u16).to_be();
            ptr = ptr.offset(1);
            *ptr = (self.additional.len() as u16).to_be();
        };

        for ques in self.questions.iter() {
            bin.extend_from_slice(&ques.to_bytes());
        }
        for rec in self.answers.iter() {
            bin.extend_from_slice(&rec.to_bytes());
        }
        for rec in self.authorities.iter() {
            bin.extend_from_slice(&rec.to_bytes());
        }
        for rec in self.additional.iter() {
            bin.extend_from_slice(&rec.to_bytes());
        }

        bin
    }
}

impl TryFrom<&[u8]> for Packet {
    type Error = DnsError;

    fn try_from(buffer: &[u8]) -> Result<Self, DnsError> {
        if buffer.len() < Header::SIZE {
            return Err(DnsError::InvalidPacketData);
        }

        let mut packet = Packet::new();

        packet.header = Header::try_from(&buffer[..Header::SIZE].try_into()?)?;
        let mut buffer_idx = Header::SIZE;

        // Parse questions from buffer
        for _ in 0..packet.header.ques_count {
            // Resolve possible pointers in the questions name
            let name_byte_len = get_name_range(&buffer[buffer_idx..])?;
            let resolved_name_buffer = resolve_pointer_in_name(
                &buffer[buffer_idx..buffer_idx + name_byte_len],
                buffer,
                buffer_idx,
            )?;
            let q_name = FQDN::try_from(&resolved_name_buffer[..])?;
            buffer_idx += name_byte_len;

            let q_type = QType::try_from(u16::from_be_bytes(
                buffer[buffer_idx..buffer_idx + 2].try_into()?,
            ))?;
            buffer_idx += 2;

            #[cfg(not(feature = "mdns"))]
            let q_class = QClass::try_from(u16::from_be_bytes(
                buffer[buffer_idx..buffer_idx + 2].try_into()?,
            ))?;
            #[cfg(feature = "mdns")]
            let (q_class, unicast_response) = {
                const MDNS_UNICAST_RESPONSE: u16 = 1 << 15;
                let bin_val = u16::from_be_bytes(buffer[buffer_idx..buffer_idx + 2].try_into()?);
                if bin_val & MDNS_UNICAST_RESPONSE > 0 {
                    (QClass::try_from(bin_val & !MDNS_UNICAST_RESPONSE)?, true)
                } else {
                    (QClass::try_from(bin_val)?, false)
                }
            };
            buffer_idx += 2;

            packet.questions.push(Question {
                q_name,
                q_type,
                q_class,
                #[cfg(feature = "mdns")]
                unicast_response,
            });
        }

        // Closure function to parse records from buffer
        let parse_record = |buffer: &[u8],
                            buffer_idx: &mut usize|
         -> Result<ResourceRecord, DnsError> {
            // Resolve possible pointers in the records name
            let name_byte_len = get_name_range(&buffer[*buffer_idx..])?;
            let resolved_name_buffer = resolve_pointer_in_name(
                &buffer[*buffer_idx..*buffer_idx + name_byte_len],
                buffer,
                *buffer_idx,
            )?;
            let a_name = FQDN::try_from(&resolved_name_buffer[..])?;
            *buffer_idx += name_byte_len;

            let a_type = RecordType::try_from(u16::from_be_bytes(
                buffer[*buffer_idx..*buffer_idx + 2].try_into()?,
            ))?;
            *buffer_idx += 2;

            #[cfg(not(feature = "mdns"))]
            let a_class = RecordClass::try_from(u16::from_be_bytes(
                buffer[*buffer_idx..*buffer_idx + 2].try_into()?,
            ))?;
            #[cfg(feature = "mdns")]
            let (a_class, cache_flush) = {
                const MDNS_ENABLE_CACHE_FLUSH: u16 = 1 << 15;
                let bin_val = u16::from_be_bytes(buffer[*buffer_idx..*buffer_idx + 2].try_into()?);
                if bin_val & MDNS_ENABLE_CACHE_FLUSH > 0 {
                    let class_val = bin_val & !MDNS_ENABLE_CACHE_FLUSH;
                    (RecordClass::try_from(class_val)?, true)
                } else {
                    (RecordClass::try_from(bin_val)?, false)
                }
            };
            *buffer_idx += 2;

            let time_to_live = u32::from_be_bytes(buffer[*buffer_idx..*buffer_idx + 4].try_into()?);
            *buffer_idx += 4;

            let data_len = u16::from_be_bytes(buffer[*buffer_idx..*buffer_idx + 2].try_into()?);
            *buffer_idx += 2;

            let data_end = *buffer_idx + data_len as usize;
            let rdata = RecordData::extract_from(
                a_type,
                &buffer[*buffer_idx..data_end],
                buffer,
                *buffer_idx,
            )?;
            *buffer_idx += data_len as usize;

            Ok(ResourceRecord {
                a_name,
                a_type,
                #[cfg(feature = "mdns")]
                cache_flush,
                a_class,
                time_to_live,
                rdata,
            })
        };

        for _ in 0..packet.header.ans_count {
            packet.answers.push(parse_record(buffer, &mut buffer_idx)?);
        }
        for _ in 0..packet.header.auth_count {
            packet
                .authorities
                .push(parse_record(buffer, &mut buffer_idx)?);
        }
        for _ in 0..packet.header.add_count {
            packet
                .additional
                .push(parse_record(buffer, &mut buffer_idx)?);
        }

        Ok(packet)
    }
}
