use std::convert::{TryFrom, TryInto};

use crate::util::ByteConvertible;
use super::{COMPRESSION_MASK, COMPRESSION_MASK_U16};
use super::header::Header;
use super::question::Question;
use super::record::{RecordClass, RecordType, RecordData, ResourceRecord};
use super::fqdn::FQDN;
use super::error::DnsError;
use super::util::{resolve_pointers_in_range, resolve_pointer};

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
            header: Header::new_query(0),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn with_question(id: u16, question: &Question) -> Self {
        Packet {
            header: Header::new_query(id),
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

impl TryFrom<&[u8]> for Packet {
    type Error = DnsError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() < Header::SIZE {
            return Err(DnsError::InvalidPacketData);
        }

        let mut packet = Packet::new();

        packet.header = Header::try_from(&buffer[..Header::SIZE].try_into()?)?;
        let mut buffer_idx = Header::SIZE;

        // Parse questions from buffer
        for _ in 0..packet.header.ques_count {
            let (q_name, name_len) = if buffer[buffer_idx] & COMPRESSION_MASK == COMPRESSION_MASK  {
                // Name represented by pointer
                let offset = (u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?) & !COMPRESSION_MASK_U16) as usize;
                (resolve_pointer(buffer, offset)?, 2)
            } else {
                // Name represented by fqdn in place
                let fqdn = FQDN::from(&buffer[buffer_idx..]);
                let len = fqdn.byte_size();
                (fqdn, len)
            };
            buffer_idx += name_len;

            let q_type = RecordType::try_from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?))?;
            buffer_idx += 2;

            let q_class = RecordClass::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?));
            buffer_idx += 2;

            packet.questions.push(Question { q_name, q_type, q_class });
        }

        // Parse answers from buffer
        for _ in 0..packet.header.ans_count+packet.header.auth_count+packet.header.add_count {
            let (a_name, name_len) = if buffer[buffer_idx] & COMPRESSION_MASK == COMPRESSION_MASK {
                // Name represented by pointer
                // let offset = (u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?) & !COMPRESSION_MASK_U16) as usize;
                let offset = (u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?) & !COMPRESSION_MASK_U16) as usize;
                (resolve_pointer(buffer, offset)?, 2)
            } else {
                // Name represented by fqdn in place
                let fqdn = FQDN::from(&buffer[buffer_idx..]);
                let len = fqdn.byte_size();
                (fqdn, len)
            };
            buffer_idx += name_len;

            let a_type = RecordType::try_from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?))?;
            buffer_idx += 2;

            let a_class = RecordClass::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?));
            buffer_idx += 2;

            let time_to_live = u32::from_be_bytes(buffer[buffer_idx..buffer_idx+4].try_into()?);
            buffer_idx += 4;

            let data_len = u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?);
            buffer_idx += 2;

            let rdata = if a_type.compression_allowed() {
                let resolved_buffer = resolve_pointers_in_range(&buffer[buffer_idx..buffer_idx+data_len as usize], buffer, buffer_idx)?;
                RecordData::from(a_type, &resolved_buffer)?
            } else {
                RecordData::from(a_type, &buffer[buffer_idx..buffer_idx+data_len as usize])?
            };
            buffer_idx += data_len as usize;

            packet.answers.push(ResourceRecord { a_name, a_type, a_class, time_to_live, rdata });
        }

        Ok(packet)
    }
}
