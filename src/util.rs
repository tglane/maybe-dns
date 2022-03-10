/// Traits

pub trait ByteConvertible {
    fn byte_size(&self) -> usize;

    fn to_bytes(&self) -> Vec<u8>;
}


/// Public functions

pub fn byte_slice_to_u16(buffer: &[u8]) -> u16 {
    assert_eq!(buffer.len(), 2);
    (buffer[0] as u16) << 8 | buffer[1] as u16
}

pub fn byte_slice_to_u32(buffer: &[u8]) -> u32 {
    assert_eq!(buffer.len(), 4);
    (buffer[0] as u32) << 24 | (buffer[1] as u32) << 16 | (buffer[2] as u32) << 8 | buffer[2] as u32
}
