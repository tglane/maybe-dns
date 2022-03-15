use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::util::ByteConvertible;

const COMPRESSION_MASK: u8 = 0b1100_0000;
const COMPRESSION_MASK_U16: u16 = 0b1100_0000_0000_0000;

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


#[derive(Copy, Clone, Debug)]
pub enum RecordClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl RecordClass {
    fn from(number: u16) -> Self {
        match number {
            2 => RecordClass::CS,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => RecordClass::IN,
        }
    }
}


#[derive(Copy, Clone, Debug)]
pub enum RecordType {
    UNDEFINED = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    PTR = 12,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
}

impl RecordType {
    fn from(number: u16) -> Self {
        match number {
             1 => RecordType::A,
             2 => RecordType::NS,
             5 => RecordType::CNAME,
            12 => RecordType::PTR,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
             _ => RecordType::UNDEFINED
        }
    }

    fn compression_allowed(&self) -> bool {
        match self {
            RecordType::A => false,
            RecordType::NS => true,
            RecordType::CNAME => true,
            RecordType::PTR => true,
            RecordType::TXT => true,
            RecordType::AAAA => false,
            RecordType::SRV => true,
            RecordType::UNDEFINED => false
        }
    }
}


#[derive(Clone, Debug)]
pub enum RecordData {
    // TODO Add missing record types
    A(Ipv4Addr),
    NS(String),
    CNAME(String),
    PTR(String),
    TXT(Vec<String>),
    AAAA(Ipv6Addr),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String
    },
    Raw(Vec<u8>)
}

impl RecordData {
    fn from(rec_type: RecordType, buffer: &[u8]) -> Self {
        match rec_type {
            RecordType::A => RecordData::A(Ipv4Addr::from(u32::from_be_bytes(buffer.try_into().unwrap()))),
            RecordType::NS => RecordData::NS(from_fqdn(buffer).0),
            RecordType::CNAME => RecordData::CNAME(from_fqdn(buffer).0),
            RecordType::PTR => RecordData::PTR(from_fqdn(buffer).0),
            RecordType::TXT => RecordData::parse_txt(buffer),
            RecordType::AAAA => RecordData::AAAA(Ipv6Addr::from(u128::from_be_bytes(buffer.try_into().unwrap()))),
            RecordType::SRV => RecordData::parse_srv(buffer),
            _ => RecordData::Raw(buffer.to_vec())
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
        let target = from_fqdn(&buffer[6..buffer.len()]).0;
        RecordData::SRV { priority, weight, port, target }
    }
}

impl ByteConvertible for RecordData {
    fn byte_size(&self) -> usize {
        match self {
            RecordData::A(_) => 4,
            RecordData::NS(ref name) => name.len() + 2,
            RecordData::CNAME(ref name) => name.len() + 2,
            RecordData::PTR(ref name) => name.len() + 2,
            RecordData::TXT(ref store) => store.iter().fold(0, |acc, elem| acc + elem.len() + 1),
            RecordData::AAAA(_) => 16,
            RecordData::SRV { priority: _, weight: _, port: _, ref target } => 2 + 2 + 2 + target.len() + 2,
            RecordData::Raw(ref buff) => buff.len(),
            _ => 0
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let buff = match self {
            RecordData::A(ref buffer) => buffer.octets().to_vec(),
            RecordData::NS(ref name) => to_fqdn(name),
            RecordData::CNAME(ref name) => to_fqdn(name),
            RecordData::PTR(ref name) => to_fqdn(name),
            RecordData::TXT(ref store) => store.iter().fold(Vec::new(), |mut buff, elem| {
                let txt_bin = elem.as_bytes();
                buff.push(txt_bin.len() as u8);
                buff.extend_from_slice(txt_bin);
                buff
            }),
            RecordData::AAAA(ref buffer) => buffer.octets().to_vec(),
            RecordData::SRV { ref priority, ref weight, ref port, ref target } => {
                let mut buff = Vec::new();
                buff.extend_from_slice(&u16::to_be_bytes(*priority));
                buff.extend_from_slice(&u16::to_be_bytes(*weight));
                buff.extend_from_slice(&u16::to_be_bytes(*port));
                buff.extend_from_slice(&to_fqdn(target));
                buff
            },
            _ => Vec::new()
        };
        buff
    }
}


#[derive(Clone, Debug)]
pub struct ResourceRecord {
    pub a_name: Vec<u8>,
    pub a_type: RecordType,
    pub a_class: RecordClass,
    pub time_to_live: u32,
    pub rdata: RecordData
}

impl ResourceRecord {
    pub fn new() -> Self {
        ResourceRecord { a_name: Vec::new(), a_type: RecordType::UNDEFINED, a_class: RecordClass::IN, time_to_live: 0, rdata: RecordData::Raw(Vec::new()) }
    }

    pub fn with(a_name: &str, a_type: RecordType, a_class: RecordClass, ttl: u32, rdata: RecordData) -> Self {
        ResourceRecord { a_name: a_name.as_bytes().to_vec(), a_type, a_class, time_to_live: ttl, rdata }
    }

    pub fn get_name_as_string(&self) -> String {
        from_fqdn(&self.a_name).0
    }

    pub fn set_name_from_string(&mut self, hostname: &str) {
        self.a_name = to_fqdn(hostname);
    }

    pub fn get_data_raw(&self) -> Vec<u8> {
        self.rdata.to_bytes()
    }
}

impl ByteConvertible for ResourceRecord {
    fn byte_size(&self) -> usize {
            self.a_name.len() +
            size_of::<u16>() +
            size_of::<u16>() +
            size_of::<u32>() +
            self.rdata.byte_size()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.a_name);
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_type as u16));
        buffer.extend_from_slice(&u16::to_be_bytes(self.a_class as u16));
        buffer.extend_from_slice(&u32::to_be_bytes(self.time_to_live));
        buffer.extend_from_slice(&u16::to_be_bytes(self.rdata.byte_size() as u16));
        buffer.extend_from_slice(&self.rdata.to_bytes());
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

        let mut packet = Packet::new();

        packet.header = Header::from_network(&buffer[..Header::SIZE].try_into().unwrap());
        let mut buffer_idx = Header::SIZE;

        // Parse questions from buffer
        for _ in 0..packet.header.ques_count {
            let (q_name, name_len) = if buffer[buffer_idx] & COMPRESSION_MASK == COMPRESSION_MASK  {
                // Name represented by pointer
                let offset = (u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap()) & !COMPRESSION_MASK_U16) as usize;
                (resolve_pointer(buffer, offset), 2)
            } else {
                // Name represented by fqdn in place
                let (_, len) = from_fqdn(&buffer[buffer_idx..]);
                (buffer[buffer_idx..buffer_idx+len].to_vec(), len)
            };
            buffer_idx += name_len;

            let q_type = RecordType::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap()));
            buffer_idx += 2;

            let q_class = RecordClass::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap()));
            buffer_idx += 2;

            packet.questions.push(Question { q_name, q_type, q_class });
        }

        // Parse answers from buffer
        for _ in 0..packet.header.ans_count+packet.header.auth_count+packet.header.add_count {
            let (a_name, name_len) = if buffer[buffer_idx] & COMPRESSION_MASK == COMPRESSION_MASK {
                // Name represented by pointer
                let offset = (u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap()) & !COMPRESSION_MASK_U16) as usize;
                (resolve_pointer(buffer, offset), 2)
            } else {
                // Name represented by fqdn in place
                let (_, len) = from_fqdn(&buffer[buffer_idx..]);
                (buffer[buffer_idx..buffer_idx+len].to_vec(), len)
            };
            buffer_idx += name_len;

            let a_type = RecordType::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap()));
            buffer_idx += 2;

            let a_class = RecordClass::from(u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap()));
            buffer_idx += 2;

            let time_to_live = u32::from_be_bytes(buffer[buffer_idx..buffer_idx+4].try_into().unwrap());
            buffer_idx += 4;

            let data_len = u16::from_be_bytes(buffer[buffer_idx..buffer_idx+2].try_into().unwrap());
            buffer_idx += 2;

            let rdata = if a_type.compression_allowed() {
                let resolved_buffer = resolve_pointers_in_range(&buffer[buffer_idx..buffer_idx+data_len as usize], buffer, buffer_idx);
                RecordData::from(a_type, &resolved_buffer)
            } else {
                RecordData::from(a_type, &buffer[buffer_idx..buffer_idx+data_len as usize])
            };
            buffer_idx += data_len as usize;

            packet.records.push(ResourceRecord { a_name, a_type, a_class, time_to_live, rdata });
        }

        Ok(packet)
    }

    pub fn id(&self) -> u16 {
        self.header.id
    }

    // TODO Implement data accessors correctly

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


fn resolve_pointers_in_range(range: &[u8], buffer: &[u8], start_in_buffer: usize) -> Vec<u8> {
    let mut resolved_buffer = range.to_vec();
    for (idx, byte) in range.iter().enumerate() {
        if *byte == COMPRESSION_MASK {
            let offset = (u16::from_be_bytes(buffer[start_in_buffer+idx..start_in_buffer+idx+2].try_into().unwrap()) & !COMPRESSION_MASK_U16) as usize;
            let resolved_pointer = resolve_pointer(buffer, offset);
            resolved_buffer.splice(idx..idx+2, resolved_pointer.iter().copied());
        }
    }
    resolved_buffer
}

fn resolve_pointer(buffer: &[u8], idx: usize) -> Vec<u8> {
    let len = buffer[idx] as usize;
    let end_idx = idx + 1 + len;
    let mut resolved = vec![len as u8; 1];
    resolved.extend_from_slice(&buffer[idx+1..idx+1+len]);

    if buffer[end_idx] == COMPRESSION_MASK {
        // Block ends on another pointer
        let nested_offset = (u16::from_be_bytes(buffer[end_idx..end_idx+2].try_into().unwrap()) & !COMPRESSION_MASK_U16) as usize;
        resolved.extend_from_slice(&resolve_pointer(buffer, nested_offset));
    } else if buffer[end_idx] != 0 {
        // Block not finished (probably reading fqdn at this point)
        resolved.extend_from_slice(&resolve_pointer(buffer, end_idx));
    } else if buffer[end_idx] == 0 {
        // Append stop byte to resolved name
        resolved.push(0);
    }

    resolved
}

fn from_fqdn(buffer: &[u8]) -> (String, usize) {
    // Read a fully-qualified domain name (fqdn) and return it as a human readable string
    let mut pos = 0_usize;
    let mut result = String::new();

    loop {
        if pos >= buffer.len() {
            break;
        }

        let len = buffer[pos];
        pos += 1;
        if pos + len as usize > buffer.len() || len == 0 {
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
    out.push(0);
    out
}
