use std::mem::size_of;
use std::convert::{TryFrom, TryInto};

use modular_bitfield::prelude::{B1, B3, B4, bitfield};

use crate::util::ByteConvertible;
use super::error::DnsError;


#[bitfield]
#[derive(Clone, Debug)]
pub struct FlagBitfield {
    pub rd: B1,
    pub tc: B1,
    pub aa: B1,
    pub opcode: B4,
    pub qr: B1,

    pub rcode: B4,
    pub z: B3,
    pub ra: B1,
}


#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum OpCode {
    StandardQuery = 0,
    InverseQuery = 1,
    ServerStatusRequest = 2,
    Reserved,
}

impl From<u8> for OpCode {
    fn from(code: u8) -> Self {
        match code {
            0 => OpCode::StandardQuery,
            1 => OpCode::InverseQuery,
            2 => OpCode::ServerStatusRequest,
            _ => OpCode::Reserved,
        }
    }
}


#[derive(Clone, Debug)]
pub struct Header {
    pub id: u16,

    pub flags: FlagBitfield,

    pub(super) ques_count: u16,
    pub(super) ans_count: u16,
    pub(super) auth_count: u16,
    pub(super) add_count: u16,
}

impl Header {
    pub(super) const SIZE: usize = size_of::<Self>();

    pub fn new_query(id: u16) -> Self {
        let flags = FlagBitfield::new().with_opcode(OpCode::StandardQuery as u8);

        Self {
            id,
            flags,
            ques_count: 0,
            ans_count: 0,
            auth_count: 0,
            add_count: 0,
        }
    }

    pub fn new_reply(id: u16, opcode: OpCode) -> Self {
        let flags = FlagBitfield::new().with_opcode(opcode as u8);
        Self {
            id,
            flags,
            ques_count: 0,
            ans_count: 0,
            auth_count: 0,
            add_count: 0,
        }
    }
}

impl ByteConvertible for Header {
    fn byte_size(&self) -> usize {
        return Self::SIZE;
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::SIZE);
        buffer.extend_from_slice(&u16::to_be_bytes(self.id));
        buffer.extend_from_slice(&self.flags.clone().into_bytes());
        buffer.extend_from_slice(&u16::to_be_bytes(self.ques_count));
        buffer.extend_from_slice(&u16::to_be_bytes(self.ans_count));
        buffer.extend_from_slice(&u16::to_be_bytes(self.auth_count));
        buffer.extend_from_slice(&u16::to_be_bytes(self.add_count));
        buffer
    }

    fn to_bytes_compressed(&self, _: &mut std::collections::HashMap<u64, usize>, _: usize) -> Vec<u8> {
        // There is nothing to compress in the header
        self.to_bytes()
    }
}

impl TryFrom<&[u8; 12]> for Header {
    type Error = DnsError;

    fn try_from(buffer: &[u8; 12]) -> Result<Self, Self::Error> {
        Ok(Header {
            id: u16::from_be_bytes(buffer[0..2].try_into()?),
            flags: FlagBitfield::from_bytes(buffer[2..4].try_into()?),
            ques_count: u16::from_be_bytes(buffer[4..6].try_into()?),
            ans_count: u16::from_be_bytes(buffer[6..8].try_into()?),
            auth_count: u16::from_be_bytes(buffer[8..10].try_into()?),
            add_count: u16::from_be_bytes(buffer[10..12].try_into()?),
        })
    }
}
