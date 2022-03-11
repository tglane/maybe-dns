use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::util::{ByteConvertible, byte_slice_to_u16};

const MDNS_RESPONSE_FLAG: u16 = 0x8400;
const MDNS_OFFSET_TOKEN: u8 = 0xC0;
const MDNS_UNKNOWN_TOKEN: u8 = 0xC1;

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
    id: u16,

    bitfield: DnsHeaderBitfield<u16>,

    ques_count: u16,
    ans_count: u16,
    auth_count: u16,
    add_count: u16,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();

    fn from_network(buffer: &[u8; size_of::<Header>()]) -> Self {
        Header {
            id: u16::from_be_bytes(buffer[0..2].try_into().unwrap()),
            bitfield: DnsHeaderBitfield(u16::from_be_bytes(buffer[2..4].try_into().unwrap())),
            ques_count: u16::from_be_bytes(buffer[4..6].try_into().unwrap()),
            ans_count: u16::from_be_bytes(buffer[6..8].try_into().unwrap()),
            auth_count: u16::from_be_bytes(buffer[8..10].try_into().unwrap()),
            add_count: u16::from_be_bytes(buffer[10..12].try_into().unwrap()),
        }
    }

    fn from_host(buffer: &[u8; size_of::<Header>()]) -> Self {
        Header {
            id: byte_slice_to_u16(&buffer[0..2]),
            bitfield: DnsHeaderBitfield(byte_slice_to_u16(&buffer[2..4])),
            ques_count: byte_slice_to_u16(&buffer[4..6]),
            ans_count: byte_slice_to_u16(&buffer[6..8]),
            auth_count: byte_slice_to_u16(&buffer[8..10]),
            add_count: byte_slice_to_u16(&buffer[10..12]),
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
        buffer.extend_from_slice(&u16::to_be_bytes(self.bitfield.0));
        buffer.extend_from_slice(&u16::to_be_bytes(self.ques_count));
        buffer.extend_from_slice(&u16::to_be_bytes(self.ans_count));
        buffer.extend_from_slice(&u16::to_be_bytes(self.auth_count));
        buffer.extend_from_slice(&u16::to_be_bytes(self.add_count));
        buffer
    }
}


#[derive(Clone, Debug)]
pub struct Question {
    pub q_name: Vec<u8>,
    pub q_type: u16,
    pub q_class: u16,
}

impl Question {
    pub fn new() -> Self {
        Question { q_name: Vec::new(), q_type: 0, q_class: 0 }
    }

    pub fn with(q_name: &str, q_type: u16, q_class: u16) -> Self {
        Question {
            q_name: to_fqdn(q_name),
            q_type,
            q_class
        }
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
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_type));
        buffer.extend_from_slice(&u16::to_be_bytes(self.q_class));
        buffer
    }
}


#[derive(Clone, Debug)]
pub enum RecordData {
    // TODO Add missing record types
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Ptr(String),
    TXT(Vec<String>),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String
    },
    Raw(Vec<u8>)
}

impl RecordData {
    pub fn from(rec_type: u16, buffer: &[u8]) -> Self {
        // TODO Add enum to prevent use of magic numbers here
        match rec_type {
             1 => RecordData::A(Ipv4Addr::from(u32::from_be_bytes(buffer.try_into().unwrap()))),
             2 => RecordData::AAAA(Ipv6Addr::from(u128::from_be_bytes(buffer.try_into().unwrap()))),
            12 => RecordData::parse_ptr(buffer),
            16 => RecordData::parse_txt(buffer),
            33 => RecordData::parse_srv(buffer),
            _  => RecordData::Raw(Vec::new())
        }
    }

    // TODO Generally check where OFFSET_TOKEN can occure

    fn parse_ptr(buffer: &[u8]) -> RecordData {
        if buffer[buffer.len()-2] == MDNS_OFFSET_TOKEN {
            // TODO Append pointed to name to the data (name compression)
            RecordData::Ptr(String::from_utf8_lossy(&buffer[1..buffer.len()-2]).to_string())
        } else {
            RecordData::Ptr(String::from_utf8_lossy(&buffer[1..]).to_string())
        }
    }

    fn parse_txt(buffer: &[u8]) -> RecordData {
        let mut txt_store = Vec::<String>::new();
        let mut idx = 0;
        while idx < buffer.len() {
            let txt_size = buffer[idx];
            txt_store.push(String::from_utf8_lossy(&buffer[idx+1..idx+txt_size as usize+1]).to_string());
            idx += txt_size as usize + 1;
        }
        RecordData::TXT(txt_store)
    }

    fn parse_srv(buffer: &[u8]) -> RecordData {
        let priority = u16::from_be_bytes(buffer[0..2].try_into().unwrap());
        let weight = u16::from_be_bytes(buffer[2..4].try_into().unwrap());
        let port = u16::from_be_bytes(buffer[4..6].try_into().unwrap());
        let target = if buffer[buffer.len()-2] == MDNS_OFFSET_TOKEN {
            String::from_utf8_lossy(&buffer[7..buffer.len()-2]).to_string()
        } else {
            String::from_utf8_lossy(&buffer[7..]).to_string()
        };
        RecordData::SRV { priority, weight, port, target }
    }
}


#[derive(Clone, Debug)]
pub struct ResourceRecord {
    pub a_name: Vec<u8>,
    pub a_type: u16,
    pub a_class: u16,
    pub time_to_live: u32,
    pub data: Vec<u8>, // TODO Improve this (not store bytes but parsed data)
}

impl ResourceRecord {
    pub fn new() -> Self {
        ResourceRecord { a_name: Vec::new(), a_type: 0, a_class: 0, time_to_live: 0, data: Vec::new() }
    }

    pub fn with(a_name: &str, a_type: u16, a_class: u16, ttl: u32, record: &ResourceRecord) -> Self {
        // TODO Implement record parsing
        ResourceRecord { a_name: a_name.as_bytes().to_vec(), a_type, a_class, time_to_live: ttl, data: Vec::new() }
    }

    pub fn get_name_as_string(&self) -> String {
        from_fqdn(&self.a_name).0
    }

    pub fn set_name_from_string(&mut self, hostname: &str) {
        self.a_name = to_fqdn(hostname);
    }

    pub fn get_data(&self) -> RecordData {
        RecordData::from(self.a_type, &self.data)
    }

    // pub fn get_data_raw(&self) -> &[u8] {
    //     &self.data
    // }
}

impl ByteConvertible for ResourceRecord {
    fn byte_size(&self) -> usize {
            self.a_name.len() +
            size_of::<u16>() +
            size_of::<u16>() +
            size_of::<u32>() +
            self.data.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.a_name);
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_type));
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class));
        buffer.extend_from_slice(&u32::to_be_bytes(self.time_to_live));
        buffer.extend_from_slice(&u16::to_be_bytes(self.data.len() as u16));
        buffer.extend_from_slice(&self.data);
        buffer
    }
}

#[derive(Clone)]
pub struct Packet {
    pub header: Header, // TODO Do not make this pub
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
            return Err(DnsError::with(""));
        }

        // Check header information
        let mut packet = Packet::new();
        packet.header = Header::from_network(&buffer[..Header::SIZE].try_into().unwrap());

        let mut buffer_idx = Header::SIZE;

        // Parse questions from buffer
        for _ in 0..packet.header.ques_count {
            let (q_name, name_len) = if buffer[buffer_idx] == MDNS_OFFSET_TOKEN || buffer[buffer_idx+1] == MDNS_UNKNOWN_TOKEN {
                // TODO Check what to do here and how to implement parsing of compressed questions
                (Vec::new(), 0)
            } else {
                // Name set as fqdn
                let (_, len) = from_fqdn(&buffer[buffer_idx..]);
                (buffer[buffer_idx..buffer_idx+len].to_vec(), len)
            };
            buffer_idx += name_len;

            let q_type = u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap());
            buffer_idx += 2;

            let q_class = u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap());
            buffer_idx += 2;

            packet.questions.push(Question { q_name, q_type, q_class });
        }

        // Parse answers from buffer
        for _ in 0..packet.header.ans_count+packet.header.auth_count+packet.header.add_count {
            let (a_name, name_len) = if buffer[buffer_idx] == MDNS_OFFSET_TOKEN || buffer[buffer_idx] == MDNS_UNKNOWN_TOKEN {
                // TODO Check what to do here and how to implement parsing of compressed answers
                println!("OFFSET_TOKEN");
                (Vec::new(), 2)
            } else {
                // Name set as fqdn
                let (_, len) = from_fqdn(&buffer[buffer_idx..]);
                (buffer[buffer_idx..buffer_idx+len].to_vec(), len)
            };
            buffer_idx += name_len;

            let a_type = u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap());
            buffer_idx += 2;

            let a_class = u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap());
            buffer_idx += 2;

            let time_to_live = u32::from_be_bytes(buffer[buffer_idx..buffer_idx+4].try_into().unwrap());
            buffer_idx += 4;

            let data_len = u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap());
            buffer_idx += 2;

            let data = Vec::from(&buffer[buffer_idx..buffer_idx+data_len as usize]);
            buffer_idx += data_len as usize;

            packet.records.push(ResourceRecord { a_name, a_type, a_class, time_to_live, data });
        }

        Ok(packet)
    }

    pub fn from_host(buffer: &[u8]) -> Result<Self, DnsError> {
        // TODO Implement
        Ok(Packet::new())
    }

    pub fn id(&self) -> u16 {
        self.header.id
    }

    // TODO Implement data accessors correctly

    pub fn add_question(&mut self, question: Question) {
        self.questions.push(question);
        self.header.ques_count += 1;
    }

    pub fn add_answer(&mut self, answer: ResourceRecord) {
        self.records.push(answer);
        self.header.ans_count += 1;
    }

    // pub fn add_authority(&mut self, authority: Authority) {
    //     self.authorities.push(authority);
    //     self.header.auth_count += 1;
    // }

    // pub fn add_additional(&mut self, additional: Additional) {
    //     self.additionals.push(additional);
    //     self.header.add_count += 1;
    // }
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

        // TODO Get binary length of auth and add records when implemented

        let mut bin = Vec::with_capacity(header_bin_len + questions_bin_len + records_bin_len);

        bin.extend_from_slice(&self.header.to_bytes());
        for ques in self.questions.iter() {
            bin.extend_from_slice(&ques.to_bytes());
        }
        for ans in self.records.iter() {
            bin.extend_from_slice(&ans.to_bytes());
        }
        // TODO Append auth and add records as binary when implemented

        bin
    }
}


#[derive(Debug, Clone)]
pub struct DnsError {
    message: String,
}

impl DnsError {
    pub fn with(message: &str) -> Self {
        DnsError { message: message.to_owned() }
    }
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "DnsError: {}", &self.message)
    }
}


fn from_fqdn(buffer: &[u8]) -> (String, usize) {
    // Read a fully-qualified domain name (fqdn) and return it as a human readable string
    let mut pos = 0_usize;
    let mut result = String::new();

    loop {
        if pos >= buffer.len() {
            // ERROR
            return (String::new(), 0);
        }

        let len = buffer[pos];
        pos += 1;
        if pos + len as usize >= buffer.len() {
            return (String::new(), 0);
        }
        if len == 0 {
            break;
        }

        if !result.is_empty() {
            result.push('.');
        }
        result.push_str(std::str::from_utf8(&buffer[pos..pos+len as usize]).unwrap());

        pos += len as usize;
    }

    (result, pos)
}

fn to_fqdn(name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut out = Vec::<u8>::with_capacity(name.len());

    let mut lock = 0;
    for idx in 0..name.len()+1 {
        if idx == name.len() || name_bytes[idx] == '.' as u8 {
            out.push((idx - lock) as u8);
            while lock < idx {
                out.push(name_bytes[lock]);
                lock += 1;
            }
            lock += 1;
        }
    }
    out.push('\0' as u8);

    out
}
