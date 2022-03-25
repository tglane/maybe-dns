use crate::util::ByteConvertible;

#[derive(Clone, Debug)]
pub struct FQDN {
    pub(super) data: Vec<Vec<u8>>,
}

impl FQDN {
    pub fn from(buffer: &[u8]) -> Self {
        let mut pos = 0_usize;
        let mut data = Vec::<Vec<u8>>::new();

        loop {
            if pos >= buffer.len() {
                break;
            }

            let len = buffer[pos];
            pos += 1;
            if pos+len as usize > buffer.len() || len == 0 {
                break;
            }

            data.push(buffer[pos..pos+len as usize].to_vec());
            pos += len as usize;
        }

        Self { data }
    }

    pub fn with(name: &str) -> Self {
        let mut data = Vec::<Vec<u8>>::new();

        let mut part_start = 0;
        for idx in 0..name.len()+1 {
            if idx == name.len() || name.as_bytes()[idx] == '.' as u8 {
                data.push(name[part_start..idx].as_bytes().to_vec());
                part_start = idx+1;
            }
        }

        Self { data }
    }

    pub fn to_string(&self) -> String {
        let mut name = String::new();
        for (idx, name_part) in self.data.iter().enumerate() {
            name.push_str(std::str::from_utf8(name_part).unwrap());
            if idx+1 != self.data.len() {
                name.push('.');
            }
        }
        name
    }

    pub fn len(&self) -> usize {
        self.data.iter().fold(0, |acc, name_part| {
            acc + name_part.len() + if acc == 0 { 0 } else { 1 }
        })
    }
}

impl ByteConvertible for FQDN {
    fn byte_size(&self) -> usize {
        self.len()+2
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.byte_size());
        for name_part in self.data.iter() {
            buffer.push(name_part.len() as u8);
            buffer.extend_from_slice(&name_part);
        }
        buffer.push(0);
        buffer
    }
}
