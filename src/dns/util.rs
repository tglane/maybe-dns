use super::{COMPRESSION_MASK, COMPRESSION_MASK_U16};
use super::fqdn::FQDN;
use super::error::DnsError;

pub(super) fn resolve_pointers_in_range(range: &[u8], buffer: &[u8], start_in_buffer: usize) -> Result<Vec<u8>, DnsError> {
    let mut resolved_buffer = range.to_vec();
    for (idx, byte) in range.iter().enumerate() {
        if *byte == COMPRESSION_MASK {
            let offset = (u16::from_be_bytes(buffer[start_in_buffer+idx..start_in_buffer+idx+2].try_into().unwrap()) & !COMPRESSION_MASK_U16) as usize;
            let resolved_pointer = resolve_pointer_impl(buffer, offset)?;
            resolved_buffer.splice(idx..idx+2, resolved_pointer.iter().copied());
        }
    }

    Ok(resolved_buffer)
}

pub(super) fn resolve_pointer(buffer: &[u8], idx: usize) -> Result<FQDN, DnsError> {
    let resolved_buffer = resolve_pointer_impl(buffer, idx)?;
    Ok(FQDN::from(&resolved_buffer[..]))
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

pub(super) fn from_fqdn(buffer: &[u8]) -> (String, usize) {
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

pub(super) fn to_fqdn(name: &str) -> Vec<u8> {
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
