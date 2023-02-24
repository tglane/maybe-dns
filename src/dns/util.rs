use std::convert::TryInto;

use super::error::DnsError;
use super::{COMPRESSION_MASK, COMPRESSION_MASK_U16};

pub(super) fn resolve_pointer_in_name(
    range: &[u8],
    buffer: &[u8],
    start_in_buffer: usize,
) -> Result<Vec<u8>, DnsError> {
    let mut resolved_buffer = range.to_vec();
    let idx = range.len() - 2;
    if range[idx] & COMPRESSION_MASK == COMPRESSION_MASK {
        let offset = (u16::from_be_bytes(
            buffer[start_in_buffer + idx..start_in_buffer + idx + 2].try_into()?,
        ) & !COMPRESSION_MASK_U16) as usize;
        if offset < start_in_buffer {
            let resolved_pointer = resolve_pointer_impl(buffer, offset)?;
            resolved_buffer.splice(idx..idx + 2, resolved_pointer.iter().copied());
        }
    }
    Ok(resolved_buffer)
}

fn resolve_pointer_impl(buffer: &[u8], idx: usize) -> Result<Vec<u8>, DnsError> {
    let len = buffer[idx] as usize;
    let end_idx = idx + 1 + len;
    let mut resolved = vec![len as u8; 1];
    resolved.extend_from_slice(&buffer[idx + 1..idx + 1 + len]);

    if buffer[end_idx] == COMPRESSION_MASK {
        // Block ends on another pointer
        let nested_offset = (u16::from_be_bytes(buffer[end_idx..end_idx + 2].try_into()?)
            & !COMPRESSION_MASK_U16) as usize;
        resolved.extend_from_slice(&resolve_pointer_impl(buffer, nested_offset)?);
    } else if buffer[end_idx] != 0 {
        // Block not finished (probably reading fqdn at this point)
        resolved.extend_from_slice(&resolve_pointer_impl(buffer, end_idx)?);
    } else if buffer[end_idx] == 0 {
        // Append stop byte to resolved name
        resolved.push(0);
    }

    Ok(resolved)
}

pub(super) fn get_name_range(buffer: &[u8]) -> Result<usize, DnsError> {
    let mut pos = 0_usize;
    loop {
        if pos >= 255 || pos >= buffer.len() {
            return Err(DnsError::LengthViolation);
        }

        let len = buffer[pos];
        pos += 1;

        if len & COMPRESSION_MASK == COMPRESSION_MASK {
            return Ok(pos + 1);
        } else if pos + len as usize > buffer.len() {
            return Err(DnsError::LengthViolation);
        } else if len == 0 {
            return Ok(pos);
        }

        pos += len as usize;
    }
}

pub(super) fn hash_bytes(name: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hash = std::collections::hash_map::DefaultHasher::new();
    name.hash(&mut hash);
    hash.finish()
}
