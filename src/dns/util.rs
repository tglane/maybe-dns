use super::{COMPRESSION_MASK, COMPRESSION_MASK_U16};
use super::error::DnsError;

pub(super) fn resolve_pointers_in_range(range: &[u8], buffer: &[u8], start_in_buffer: usize) -> Result<Vec<u8>, DnsError> {
    let mut resolved_buffer = range.to_vec();
    for (idx, byte) in range.iter().enumerate() {
        if *byte & COMPRESSION_MASK == COMPRESSION_MASK {
            let offset = (u16::from_be_bytes(buffer[start_in_buffer+idx..start_in_buffer+idx+2].try_into().unwrap()) & !COMPRESSION_MASK_U16) as usize;
            let resolved_pointer = resolve_pointer_impl(buffer, offset)?;
            resolved_buffer.splice(idx..idx+2, resolved_pointer.iter().copied());
        }
    }

    Ok(resolved_buffer)
}

fn resolve_pointer_impl(buffer: &[u8], idx: usize) -> Result<Vec<u8>, DnsError> {
    let len = buffer[idx] as usize;
    let end_idx = idx + 1 + len;
    let mut resolved = vec![len as u8; 1];
    resolved.extend_from_slice(&buffer[idx+1..idx+1+len]);

    if buffer[end_idx] == COMPRESSION_MASK {
        // Block ends on another pointer
        let nested_offset = (u16::from_be_bytes(buffer[end_idx..end_idx+2].try_into()?) & !COMPRESSION_MASK_U16) as usize;
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
