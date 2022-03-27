use std::mem::size_of;

use crate::util::ByteConvertible;
use super::error::DnsError;

bitfield!{
    #[derive(Clone, Debug)]
    pub struct DnsHeaderBitfield([u8]);
    u16;

    get_qr, set_qr: 0;
    get_opcode, set_opcode: 4, 1;
    get_aa, set_aa: 5;
    get_tc, set_tc: 6;
    get_rd, set_rd: 7;

    get_ra, set_ra: 8;
    get_z, set_z: 9;
    get_ad, set_ad: 10;
    get_cd, set_cd: 11;
    get_rcode, set_rcode: 15, 12;
}

#[derive(Clone, Debug)]
pub struct Header {
    pub(super) id: u16,

    pub(super) bitfield: DnsHeaderBitfield<u16>,

    pub(super) ques_count: u16,
    pub(super) ans_count: u16,
    pub(super) auth_count: u16,
    pub(super) add_count: u16,
}

impl Header {
    pub(super) const SIZE: usize = size_of::<Self>();

    pub(super) fn from_network(buffer: &[u8; size_of::<Header>()]) -> Result<Self, DnsError> {
        Ok(Header {
            id: u16::from_be_bytes(buffer[0..2].try_into()?),
            bitfield: DnsHeaderBitfield(u16::from_be_bytes(buffer[2..4].try_into()?)),
            ques_count: u16::from_be_bytes(buffer[4..6].try_into()?),
            ans_count: u16::from_be_bytes(buffer[6..8].try_into()?),
            auth_count: u16::from_be_bytes(buffer[8..10].try_into()?),
            add_count: u16::from_be_bytes(buffer[10..12].try_into()?),
        })
    }

    // TODO Add accessor for struct fields
}

impl ByteConvertible for Header {
    fn byte_size(&self) -> usize {
        return Self::SIZE;
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::SIZE);
        buffer.extend_from_slice(&u16::to_be_bytes(self.id));
        buffer.extend_from_slice(&u16::to_be_bytes(self.bitfield.0));
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
