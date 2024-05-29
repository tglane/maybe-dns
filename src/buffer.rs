use std::collections::HashMap;
use std::convert::From;

use crate::error::DnsError;
use crate::fqdn::FQDN;

/// Helper struct used for creation of DNS packets and its parts from binary data
/// A pointer called pos marks the current reading position but it is alway possible to perform
/// random reads via the Index trait to allow the parsing of compressed DNS data.
#[derive(Debug)]
pub struct DnsBuffer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DnsBuffer<'a> {
    pub fn sub_buffer(&mut self, len: usize) -> Result<DnsBuffer, DnsError> {
        Ok(Self {
            data: &self.data[0..self.pos + len],
            pos: self.pos,
        })
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn advance(&mut self, len: usize) {
        self.pos += len;
    }

    pub fn peek_bytes(&self, len: usize) -> Result<&[u8], DnsError> {
        if self.pos + len > self.data.len() {
            return Err(DnsError::LengthViolation);
        }
        Ok(&self.data[self.pos..self.pos + len])
    }

    pub fn extract_bytes(&mut self, len: usize) -> Result<&[u8], DnsError> {
        if self.pos + len > self.data.len() {
            return Err(DnsError::LengthViolation);
        }

        self.pos += len;
        Ok(&self.data[self.pos - len..self.pos])
    }

    pub fn extract_u8(&mut self) -> Result<u8, DnsError> {
        Ok(u8::from_be_bytes(self.extract_bytes(1)?.try_into()?))
    }

    pub fn extract_u16(&mut self) -> Result<u16, DnsError> {
        Ok(u16::from_be_bytes(self.extract_bytes(2)?.try_into()?))
    }

    pub fn extract_u32(&mut self) -> Result<u32, DnsError> {
        Ok(u32::from_be_bytes(self.extract_bytes(4)?.try_into()?))
    }

    pub fn extract_u16_as<TwoBytesType>(&mut self) -> Result<TwoBytesType, DnsError>
    where
        TwoBytesType: TryFrom<u16, Error = DnsError>,
    {
        TwoBytesType::try_from(self.extract_u16()?)
    }

    pub fn extract_character_string(&mut self) -> Result<Vec<u8>, DnsError> {
        let len = self.extract_u8()? as usize;
        let mut data = Vec::with_capacity(len);
        data.extend_from_slice(self.extract_bytes(len)?);
        Ok(data)
    }

    pub fn extract_string(&mut self) -> Result<String, DnsError> {
        let string = String::from_utf8(self.extract_character_string()?)
            .map_err(|_| DnsError::LengthViolation)?;
        Ok(string)
    }

    pub fn extract_fqdn(&mut self) -> Result<FQDN, DnsError> {
        use crate::{COMPRESSION_MASK, COMPRESSION_MASK_U16};

        let mut data = Vec::<Vec<u8>>::new();
        let mut org_pos = None;
        loop {
            let len = self.data[self.pos];
            if len & COMPRESSION_MASK == COMPRESSION_MASK {
                // Instead of returning an error we should look up what the pointer value is
                // and reolve the fqdn here

                if org_pos.is_none() {
                    org_pos = Some(self.pos + 1);
                }

                self.pos = (u16::from_be_bytes(self.peek_bytes(2)?.try_into()?)
                    & !COMPRESSION_MASK_U16) as usize;

                if self.pos >= org_pos.unwrap_or(0) {
                    self.pos = org_pos.unwrap_or(0);
                    return Err(DnsError::UnresolveableCompressionPointer);
                }
            } else if self.pos + len as usize > self.data.len() {
                // Length encoded in FQDN would run out of the buffer
                return Err(DnsError::LengthViolation);
            } else if len == 0 {
                // Read stop byte indicating end of FQDN
                // First we need to reset the position pointer to its original position
                if let Some(org_pos) = org_pos {
                    self.pos = org_pos;
                }

                self.pos += 1;
                return Ok(FQDN::from(data));
            } else {
                // Consume next part to FQDN
                self.pos += 1;
                data.push(self.data[self.pos..self.pos + len as usize].to_vec());
                self.pos += len as usize;
            }
        }
    }

    pub fn generate_name_index(&self) -> HashMap<u64, usize> {
        todo!("Iterate through buffer and find FQDN and insert their hashes into the result hashmap with their index in the buffer")
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data
    }
}

impl<'a> From<&'a [u8]> for DnsBuffer<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self {
            data: value,
            pos: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DnsBuffer;

    const ARR: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

    #[test]
    fn slice_range() {
        let mut buffer = DnsBuffer::from(&ARR[..]);

        buffer.advance(2);
        assert_eq!(buffer.peek_bytes(3).unwrap_or(&[]), &ARR[2..5]);
        assert_eq!(buffer.extract_bytes(3).unwrap_or(&[]), &ARR[2..5]);

        assert_eq!(buffer.peek_bytes(4).unwrap_or(&[]), &ARR[5..9]);
    }
}
