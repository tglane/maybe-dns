use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::header::{Header, OpCode, ResponseCode};
use crate::question::Question;
use crate::resource::ResourceRecord;

/// Represents a complete DNS packet/message.
/// A message is divided into five sections, some of which are empty in certain cases.
///
/// In wire-format a packet has the following representation:
///     +---------------------+
///     |        Header       |
///     +---------------------+
///     |       Question      | the question for the name server
///     +---------------------+
///     |        Answer       | RRs answering the question
///     +---------------------+
///     |      Authority      | RRs pointing toward an authority
///     +---------------------+
///     |      Additional     | RRs holding additional information
///     +---------------------+
///
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Packet {
    /// Header section of a packet is always present and includes fields that specify
    /// which of the remaining sections are present, and also specifiy wether the
    /// message is a query or a reponse to some query or something else.
    /// Contains the configuration of the message data.
    header: Header,

    /// Contains fields that each describe a question to a name server.
    questions: Vec<Question>,

    /// Contains resource records that answer the questions.
    answers: Vec<ResourceRecord>,

    /// Contains resource records that point toward a authoritative name server.
    authorities: Vec<ResourceRecord>,

    /// Contains resource records which relate to the query, but are not strictly
    /// anwsers for the questions.
    additional: Vec<ResourceRecord>,
}

impl Packet {
    /// Create a new packet configured as a dns query.
    /// This sets the necessary flags to make it a query dns packet. Other fields remain defaulted.
    /// This should only be used to query information from a name server.
    pub fn new_query(id: u16, recursion_desired: bool) -> Self {
        Packet {
            header: Header::new_query(id, recursion_desired),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Create a new packet configured as a dns reply.
    /// This sets the necessary flags to make it a reply dns packet. Other fields remain defaulted.
    /// This should only be used to answer dns queries.
    pub fn new_reply(id: u16) -> Self {
        Self {
            header: Header::new_reply(id, OpCode::StandardQuery),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Create a new packet configured as a dns query preoccupied with a list of `Questions`.
    /// This sets the necessary flags to make it a query dns packet. Other fields remain defaulted.
    /// This should only be used to query information from a name server.
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

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn set_header(&mut self, header: Header) {
        self.header = header;
    }

    pub fn questions(&self) -> &[Question] {
        &self.questions
    }

    pub fn questions_mut(&mut self) -> &mut Vec<Question> {
        &mut self.questions
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

    /// Creates a binary representation of a `Packet` with DNS compression enabled.
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
        // SAFETY: Safe to dereference the pointer because the vector the pointer points to
        // was created with the expected capacity of the header struct beforehand
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
        let mut buffer = DnsBuffer::from(buffer);
        let packet = Packet::try_from(&mut buffer)?;
        Ok(packet)
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Packet {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let mut packet = Packet::default();

        packet.set_header(Header::try_from(buffer as &mut _)?);

        // Parse questions from buffer
        let mut questions = Vec::with_capacity(packet.header.ques_count as usize);
        for _ in 0..packet.header.ques_count {
            questions.push(Question::try_from(buffer as &mut _)?);
        }
        packet.questions = questions;

        // Parse answer records from buffer
        let mut answers = Vec::with_capacity(packet.header.ans_count as usize);
        for _ in 0..packet.header.ans_count {
            // packet.add_answer(ResourceRecord::try_from(buffer as &mut _)?);
            answers.push(ResourceRecord::try_from(buffer as &mut _)?);
        }
        packet.answers = answers;

        // Parse authority records from buffer
        let mut authorities = Vec::with_capacity(packet.header.auth_count as usize);
        for _ in 0..packet.header.auth_count {
            authorities.push(ResourceRecord::try_from(buffer as &mut _)?);
        }
        packet.authorities = authorities;

        // Parse additional records from buffer
        let mut additionals = Vec::with_capacity(packet.header.add_count as usize);
        for _ in 0..packet.header.add_count {
            additionals.push(ResourceRecord::try_from(buffer as &mut _)?);
        }
        packet.additional = additionals;

        Ok(packet)
    }
}
