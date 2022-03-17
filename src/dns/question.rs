use std::mem::size_of;

use crate::util::ByteConvertible;
use super::record::{RecordClass, RecordType};
use super::util::{to_fqdn, from_fqdn};

#[derive(Clone, Debug)]
pub struct Question {
    pub q_name: Vec<u8>,
    pub q_type: RecordType,
    pub q_class: RecordClass,
}

impl Question {
    pub fn new() -> Self {
        Question { q_name: Vec::new(), q_type: RecordType::UNDEFINED, q_class: RecordClass::IN }
    }

    pub fn with(q_name: &str, q_type: RecordType, q_class: RecordClass) -> Self {
        Question { q_name: to_fqdn(q_name), q_type, q_class }
    }

    pub fn get_name_as_string(&self) -> String {
        from_fqdn(&self.q_name).0
    }

    pub fn set_name_from_string(&mut self, hostname: &str) {
        self.q_name = to_fqdn(hostname);
    }
}

impl ByteConvertible for Question {
    fn byte_size(&self) -> usize {
        self.q_name.len() +
        size_of::<u16>() +
        size_of::<u16>()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.q_name);
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_class as u16));
        buffer
    }
}
