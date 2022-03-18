use crate::util::ByteConvertible;
use super::header::{DnsHeaderBitfield, Header};
use super::question::Question;
use super::record::{RecordClass, RecordType, RecordData, ResourceRecord};
use super::error::DnsError;
use super::util::{resolve_pointers_in_range, resolve_pointer, from_fqdn, COMPRESSION_MASK, COMPRESSION_MASK_U16};

#[derive(Clone)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub records: Vec<ResourceRecord>,
}

#[allow(dead_code)]
impl Packet {
    pub fn new() -> Self {
        Packet {
            header: Header {
                id: 0,
                bitfield: DnsHeaderBitfield(0),
                ques_count: 0,
                ans_count: 0,
                auth_count: 0,
                add_count: 0,
            },
            questions: Vec::new(),
            records: Vec::new(),
        }
    }

    pub fn with_question(id: u16, question: &Question) -> Self {
        Packet {
            header: Header {
                id,
                bitfield: DnsHeaderBitfield(0),
                ques_count: 1_u16,
                ans_count: 0,
                auth_count: 0,
                add_count: 0,
            },
            questions: vec![question.clone()],
            records: Vec::new(),
        }
    }

    pub fn from_network(buffer: &[u8]) -> Result<Self, DnsError> {
        if buffer.len() < Header::SIZE {
            return Err(DnsError::InvalidPacketData);
        }

        let mut packet = Packet::new();

        packet.header = Header::from_network(&buffer[..Header::SIZE].try_into()?)?;
        let mut buffer_idx = Header::SIZE;

        // Parse questions from buffer
        for _ in 0..packet.header.ques_count {
            let (q_name, name_len) = if buffer[buffer_idx] & COMPRESSION_MASK == COMPRESSION_MASK  {
                // Name represented by pointer
                let offset = (u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?) & !COMPRESSION_MASK_U16) as usize;
                (resolve_pointer(buffer, offset)?, 2)
            } else {
                // Name represented by fqdn in place
                let (_, len) = from_fqdn(&buffer[buffer_idx..]);
                (buffer[buffer_idx..buffer_idx+len].to_vec(), len)
            };
            buffer_idx += name_len;

            let q_type = RecordType::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?))?;
            buffer_idx += 2;

            let q_class = RecordClass::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?));
            buffer_idx += 2;

            packet.questions.push(Question { q_name, q_type, q_class });
        }

        // Parse answers from buffer
        for _ in 0..packet.header.ans_count+packet.header.auth_count+packet.header.add_count {
            let (a_name, name_len) = if buffer[buffer_idx] & COMPRESSION_MASK == COMPRESSION_MASK {
                // Name represented by pointer
                let offset = (u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?) & !COMPRESSION_MASK_U16) as usize;
                (resolve_pointer(buffer, offset)?, 2)
            } else {
                // Name represented by fqdn in place
                let (_, len) = from_fqdn(&buffer[buffer_idx..]);
                (buffer[buffer_idx..buffer_idx+len].to_vec(), len)
            };
            buffer_idx += name_len;

            let a_type = RecordType::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into()?))?;
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

            packet.records.push(ResourceRecord { a_name, a_type, a_class, time_to_live, rdata });
        }

        Ok(packet)
    }

    pub fn id(&self) -> u16 {
        self.header.id
    }

    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.ques_count += 1;
    }

    pub fn add_resource(&mut self, resource: ResourceRecord) {
        self.records.push(resource);
        self.header.ans_count += 1;
    }
}

impl ByteConvertible for Packet {
    fn byte_size(&self) -> usize {
        let mut size = Header::SIZE;
        for ques in self.questions.iter() {
            size += ques.byte_size();
        }
        for ans in self.records.iter() {
            size += ans.byte_size();
        }
        size
    }

    fn to_bytes(&self) -> Vec<u8> {
        let header_bin_len = self.header.byte_size();

        let mut questions_bin_len = 0;
        for ques in self.questions.iter() {
            questions_bin_len += ques.byte_size();
        }

        let mut records_bin_len = 0;
        for ans in self.records.iter() {
            records_bin_len += ans.byte_size();
        }

        let mut bin = Vec::with_capacity(header_bin_len + questions_bin_len + records_bin_len);

        bin.extend_from_slice(&self.header.to_bytes());
        for ques in self.questions.iter() {
            bin.extend_from_slice(&ques.to_bytes());
        }
        for ans in self.records.iter() {
            bin.extend_from_slice(&ans.to_bytes());
        }

        bin
    }
}
