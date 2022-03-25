use std::mem::size_of;

use crate::util::ByteConvertible;
use super::record::{RecordClass, RecordType};
use super::fqdn::FQDN;

#[derive(Clone, Debug)]
pub struct Question {
    pub q_name: FQDN,
    pub q_type: RecordType,
    pub q_class: RecordClass,
}

impl Question {
    pub fn with(q_name: &str, q_type: RecordType, q_class: RecordClass) -> Self {
        Question { q_name: FQDN::with(q_name), q_type, q_class }
    }
}

impl ByteConvertible for Question {
    fn byte_size(&self) -> usize {
        self.q_name.len() +
        size_of::<u16>() +
        size_of::<u16>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.q_name.byte_size() + size_of::<u16>() + size_of::<u16>());
        buffer.extend_from_slice(&self.q_name.to_bytes());
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_class as u16));
        buffer
    }
}
