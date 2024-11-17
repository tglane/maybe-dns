use modular_bitfield::prelude::{bitfield, B1, B3, B4};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::mem::{size_of, transmute};

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;

/// Header section of a packet is always present and includes fields that specify
/// which of the remaining sections are present, and also specifiy wether the
/// message is a query or a reponse to some query or something else.
/// Contains the configuration of the message data.
///
/// The wire-format of a header has the following representation:
///                                   1  1  1  1  1  1
///     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      ID                       |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    QDCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ANCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    NSCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ARCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The identification field is used to match responses with queries.
    pub(super) id: u16,

    /// Various flags to configure a dns packet.
    flags: FlagBitfield,

    /// Number of question records in the dns packet.
    pub(super) ques_count: u16,

    /// Number of answer records in the dns packet.
    pub(super) ans_count: u16,

    /// Number of authority records in the dns packet.
    pub(super) auth_count: u16,

    /// Number of additional records in the dns packet.
    pub(super) add_count: u16,
}

impl Header {
    /// The number of bytes to represent a dns header.
    pub(super) const SIZE: usize = size_of::<Self>();

    /// Create a new header for a query dns packet.
    /// This sets the necessary flags to make it a query dns packet. Other fields remain defaulted.
    pub fn new_query(id: u16, recursion_desired: bool) -> Self {
        let flags = FlagBitfield::new()
            .with_opcode(OpCode::StandardQuery as u8)
            .with_rd(recursion_desired as u8);

        Self {
            id,
            flags,
            ques_count: 0,
            ans_count: 0,
            auth_count: 0,
            add_count: 0,
        }
    }

    /// Create a new header for a reply dns packet.
    /// This sets the necessary flags to make it a reply dns packet. Other fields remain defaulted.
    pub fn new_reply(id: u16, opcode: OpCode) -> Self {
        let flags = FlagBitfield::new().with_opcode(opcode as u8).with_qr(1);
        Self {
            id,
            flags,
            ques_count: 0,
            ans_count: 0,
            auth_count: 0,
            add_count: 0,
        }
    }

    pub fn recursion_desired(&self) -> bool {
        self.flags.rd() != 0
    }

    pub fn set_recursion_desired(&mut self, rd: bool) {
        // SAFETY: rd is represented by a single bit in the bitfield
        self.flags.set_rd(unsafe { transmute(rd) });
    }

    pub fn truncation(&self) -> bool {
        self.flags.tc() != 0
    }

    pub fn set_truncation(&mut self, tc: bool) {
        // SAFETY: tc is represented by a single bit in the bitfield
        self.flags.set_tc(unsafe { transmute(tc) });
    }

    pub fn authoritative_answer(&self) -> bool {
        self.flags.aa() != 0
    }

    pub fn set_authoritative_answer(&mut self, aa: bool) {
        // SAFETY: aa is represented by a single bit in the bitfield
        self.flags.set_aa(unsafe { transmute(aa) });
    }

    pub fn opcode(&self) -> OpCode {
        OpCode::from(self.flags.opcode())
    }

    pub fn set_opcode(&mut self, opcode: OpCode) {
        // SAFETY: opcode enum is represented by a four bits in the bitfield and can only be set
        // from the constructor in a controlled way
        self.flags.set_opcode(unsafe { transmute(opcode) });
    }

    pub fn query_response(&self) -> bool {
        self.flags.qr() != 0
    }

    pub fn set_query_response(&mut self, qr: bool) {
        // SAFETY: qr is represented by a single bit in the bitfield
        self.flags.set_qr(unsafe { transmute(qr) });

        // Some fields can only be set by a server
        if !qr {
            self.flags.set_ra(0);
            // SAFETY: opcode enum is represented by a four bits in the bitfield and can only be set
            // from the constructor in a controlled way
            self.flags
                .set_rcode(unsafe { transmute(ResponseCode::NoError) });
        }
    }

    pub fn response_code(&self) -> ResponseCode {
        ResponseCode::try_from(self.flags.rcode()).unwrap()
    }

    pub fn set_response_code(&mut self, response_code: ResponseCode) {
        // SAFETY: opcode enum is represented by a four bits in the bitfield and can only be set
        // from the constructor in a controlled way
        self.flags.set_rcode(unsafe { transmute(response_code) });

        // Only set by a server
        if response_code != ResponseCode::NoError {
            self.flags.set_qr(1);
        }
    }

    pub fn recursion_available(&self) -> bool {
        self.flags.ra() != 0
    }

    pub fn set_recursion_available(&mut self, ra: bool) {
        // SAFETY: ra is represented by a single bit in the bitfield
        self.flags.set_ra(unsafe { transmute(ra) });

        // Only set by a server
        if ra {
            self.flags.set_qr(1);
        }
    }
}

impl ByteConvertible for Header {
    fn byte_size(&self) -> usize {
        Self::SIZE
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
}

impl CompressedByteConvertible for Header {
    fn byte_size_compressed(&self, _: &mut HashMap<u64, usize>, _: usize) -> usize {
        // There is nothing to compress in the header
        self.byte_size()
    }

    fn to_bytes_compressed(&self, _: &mut HashMap<u64, usize>, _: usize) -> Vec<u8> {
        // There is nothing to compress in the header
        self.to_bytes()
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Header {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer) -> Result<Self, Self::Error> {
        Ok(Header {
            id: buffer.extract_u16()?,
            flags: FlagBitfield::from_bytes(buffer.extract_bytes(2)?.try_into()?),
            ques_count: buffer.extract_u16()?,
            ans_count: buffer.extract_u16()?,
            auth_count: buffer.extract_u16()?,
            add_count: buffer.extract_u16()?,
        })
    }
}

/// Representation of the bitflags that are present in the header of a dns packet.
#[bitfield]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlagBitfield {
    /// Recursion desired is set by a client to indicate the client wants the server to recursively
    /// query further server by itself
    rd: B1,
    /// Truncation bit indicates messages that are too large to be sent in a single message
    tc: B1,
    /// Authoritative answer is only set by a server and indicates that it is authoritative
    /// responsible for the queried domains
    aa: B1,
    /// Opcode is set by the client and copied into the answer and indicates the query type
    opcode: B4,
    /// Query/Response Bit indicates wether this is a query (0) or a response (1)
    qr: B1,
    /// Response code is only set in responses to give information about the type of answer
    rcode: B4,
    /// Reserved/Unused
    #[allow(unused)]
    z: B3,
    /// Recursion available is set by the server to indicate its capability to handle queries recursively
    ra: B1,
}

/// Enum representation of the operation modes a dns packet can be set to.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum OpCode {
    /// Standard query requests.
    StandardQuery = 0,
    /// Inverse query lookup.
    InverseQuery = 1,
    /// Status request by a server.
    ServerStatusRequest = 2,
    /// Reserved for future use.
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

/// Set for dns response packets to indicate the status of the request.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ResponseCode {
    /// No error condition.
    NoError = 0,

    /// The name server was unable to interpret the query.
    FormatError = 1,

    /// The name server was unable to process this query due to a problem with the name server.
    ServerFailure = 2,

    /// Meaningful only for responses from an authoritative name server, this code signifies that
    /// the domain name referenced in the query does not exist.
    NameError = 3,

    /// Not Implemented - The name server does not support the requested kind of query.
    NotImplemented = 4,

    /// The name server refuses to perform the specified operation for policy reasons. For example,
    /// a name server may not wish to provide the information to the particular requester, or a
    /// name server may not wish to perform a particular operation (e.g., zone transfer) for
    /// particular data.
    Refused = 5,

    /// Some name that ought not to exist, does exist.
    YXDomain = 6,

    /// Some RRset taht ought not to exist, does exist.
    YXRRSet = 7,

    /// Some RRSet taht ought to exist, does not exist.
    NXRRSet = 8,

    /// Server not authoritative for the zone.
    NotAuth = 9,

    /// Name not in zone.
    NotZone = 10,
}

impl TryFrom<u8> for ResponseCode {
    type Error = DnsError;

    fn try_from(code: u8) -> Result<Self, DnsError> {
        match code {
            0 => Ok(ResponseCode::NoError),
            1 => Ok(ResponseCode::FormatError),
            2 => Ok(ResponseCode::ServerFailure),
            3 => Ok(ResponseCode::NameError),
            4 => Ok(ResponseCode::NotImplemented),
            5 => Ok(ResponseCode::Refused),
            6 => Ok(ResponseCode::YXDomain),
            7 => Ok(ResponseCode::YXRRSet),
            8 => Ok(ResponseCode::NXRRSet),
            9 => Ok(ResponseCode::NotAuth),
            10 => Ok(ResponseCode::NotZone),
            _ => Err(DnsError::InvalidResponseCode(code)),
        }
    }
}
