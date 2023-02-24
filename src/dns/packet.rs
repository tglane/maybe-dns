use std::convert::{TryFrom, TryInto};

use super::byteconvertible::ByteConvertible;
use super::error::DnsError;
use super::fqdn::FQDN;
use super::header::{Header, OpCode};
use super::question::{QClass, QType, Question};
use super::resource::{RecordClass, RecordData, RecordType, ResourceRecord};
use super::util::{get_name_range, resolve_pointer_in_name};

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl Packet {
    pub fn new() -> Self {
        Packet {
            header: Header::new_query(0, false),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
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

    pub fn with_question(id: u16, rc: bool, question: &Question) -> Self {
        Packet {
            header: Header::new_query(id, rc),
            questions: vec![question.clone()],
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn byte_size(&self) -> usize {
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

    pub fn to_bytes(&self) -> Vec<u8> {
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

impl Default for Packet {
    fn default() -> Self {
        Self {
            header: Header::new_query(0, false),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
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

            let q_class = QClass::from(u16::from_be_bytes(
                buffer[buffer_idx..buffer_idx + 2].try_into()?,
            ));
            buffer_idx += 2;

            packet.questions.push(Question {
                q_name,
                q_type,
                q_class,
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

            let a_class = RecordClass::from(u16::from_be_bytes(
                buffer[*buffer_idx..*buffer_idx + 2].try_into()?,
            ));
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
