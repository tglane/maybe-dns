use std::collections::BTreeSet;
use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The CSYNC RRType contains, in its RDATA component, these parts: an
/// SOA serial number, a set of flags, and a simple bit-list indicating
/// the DNS RRTypes in the child that should be processed by the parental
/// agent in order to modify the DNS delegation records within the
/// parent's zone for the child DNS operator. Child DNS operators
/// wanting a parental agent to perform the synchronization steps
/// outlined in this document MUST publish a CSYNC record at the apex of
/// the child zone. Parental agent implementations MAY choose to query
/// child zones for this record and process DNS record data as indicated
/// by the Type Bit Map field in the RDATA of the CSYNC record. How the
/// data is processed is described in Section 3.
///
/// Parental agents MUST process the entire set of child data indicated
/// by the Type Bit Map field (i.e., all record types indicated along
/// with all of the necessary records to support processing of that type)
/// or else parental agents MUST NOT make any changes to parental records
/// at all. Errors due to unsupported Type Bit Map bits, or otherwise
/// nonpunishable data, SHALL result in no change to the parent zone's
/// delegation information for the child. Parental agents MUST ignore a
/// child's CSYNC RDATA set if multiple CSYNC resource records are found;
/// only a single CSYNC record should ever be present.
///
/// The parental agent MUST perform DNSSEC validation ([RFC4033]
/// [RFC4034] [RFC4035]), of the CSYNC RRType data and MUST perform
/// DNSSEC validation of any data to be copied from the child to the
/// parent. Parents MUST NOT process any data from any of these records
/// if any of the validation results indicate anything other than
/// "Secure" [RFC4034] or if any the required data cannot be successfully
/// retrieved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Csync {
    /// The SOA Serial field contains a copy of the 32-bit SOA serial number
    /// from the child zone. If the soaminimum flag is set, parental agents
    /// querying children's authoritative servers MUST NOT act on data from
    /// zones advertising an SOA serial number less than this value. See
    /// [RFC1982] for properly implementing "less than" logic. If the
    /// soaminimum flag is not set, parental agents MUST ignore the value in
    /// the SOA Serial field. Clients can set the field to any value if the
    /// soaminimum flag is unset, such as the number zero.
    pub soa_serial: u32,

    /// The Flags field contains 16 bits of boolean flags that define
    /// operations that affect the processing of the CSYNC record.
    pub flags: Flags,

    /// The Type Bit Map field indicates the record types to be processed by
    /// the parental agent, according to the procedures in Section 3. The
    /// Type Bit Map field is encoded in the same way as the Type Bit Map
    /// field of the NSEC record, described in [RFC4034], Section 4.1.2.  If
    /// a bit has been set that a parental agent implementation does not
    /// understand, the parental agent MUST NOT act upon the record.
    /// Specifically, a parental agent must not simply copy the data, and it
    /// must understand the semantics associated with a bit in the Type Bit
    /// Map field that has been set to 1.
    pub types: BTreeSet<RecordType>,
}

impl Csync {
    pub fn new(soa_serial: u32, flags: Flags, types: BTreeSet<RecordType>) -> Self {
        Self {
            soa_serial,
            flags,
            types,
        }
    }
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Csync {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        let soa_serial = buffer.extract_u32()?;
        let flags = buffer.extract_u16()?.try_into()?;

        // Extract the mentioned record types from the binary data representation
        let mut types = BTreeSet::new();
        while buffer.remaining() > 0 {
            let window_num = buffer.extract_u8()? as u16;
            let window_len = buffer.extract_u8()? as u16;

            // By extracting the RRTypes from the bitmap it is "guaranteed" that the resulting vec
            // self.types is sorted
            let bitmap = buffer.extract_bytes(window_len as usize)?;
            for (index, octet) in bitmap.iter().enumerate() {
                for i in 0..8 {
                    if (octet << i) & 0x80 > 0 {
                        let bit_position = (256 * window_num) + (8 * index as u16) + i;
                        types.insert(RecordType::try_from(bit_position)?);
                    }
                }
            }
        }

        Ok(Self {
            soa_serial,
            flags,
            types,
        })
    }
}

impl RData for Csync {
    fn record_type(&self) -> RecordType {
        RecordType::CSYNC
    }

    fn into_record_data(self) -> RecordData {
        RecordData::CSYNC(self)
    }
}

impl ByteConvertible for Csync {
    #[inline]
    fn byte_size(&self) -> usize {
        let mut byte_size = std::mem::size_of::<u32>() + std::mem::size_of::<u16>();

        let mut rtype_iter = self.types.iter().peekable();
        let mut block_num: u16 = 0;
        let mut last_rtype = None;
        loop {
            let rtype = rtype_iter.next();
            if rtype.is_none() || *rtype.unwrap() as u16 - (block_num * 32) > 255 {
                byte_size += 2; // window number and block length
                let num_octets = ((last_rtype.unwrap_or(0) / 8) - (32 * block_num)) as usize;
                byte_size += num_octets + 1; // Octet index of last entry equals the block length

                if rtype.is_none() {
                    break;
                }
                block_num += 1;
            }
            last_rtype = rtype.map(|r| *r as u16);
        }

        byte_size
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend(u32::to_be_bytes(self.soa_serial));
        buffer.extend(u16::to_be_bytes(self.flags.into()));

        // Encode windows {u8 windowblock, u8 bitmaplength, 0-32u8 bitmap}
        // Each Block is 0-255 upper octet of types, length if 0-32
        let mut block_num = 0;
        let mut block_len = 0_u8;
        let mut block_data = [0_u8; 32];

        let mut rtype_iter = self.types.iter().peekable();
        loop {
            let rtype = rtype_iter.next();
            if rtype.is_none() || *rtype.unwrap() as u16 - (block_num * 32) > 255 {
                // Finish block by pushing it into the output buffer
                buffer.push(block_num as u8);
                buffer.push(block_len + 1_u8);
                buffer.extend_from_slice(&block_data[0..=block_len as usize]);

                if rtype.is_none() {
                    break;
                }
                block_num += 1;
                block_data.fill(0);
            }

            block_len = ((*rtype.unwrap() as u16 / 8) - (32 * block_num)) as u8;
            let bit_in_octet = *rtype.unwrap() as u16 % 8;
            block_data[block_len as usize] |= 128 >> bit_in_octet as u8;
        }

        buffer
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct Flags(u16);

impl Flags {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn immediate(&self) -> bool {
        (self.0 & 1) != 0
    }

    pub fn set_immediate(&mut self, active: bool) {
        if active {
            self.0 |= 1;
        } else {
            self.0 &= !1;
        }
    }

    pub fn soa_minimum(&self) -> bool {
        (self.0 & 2) != 0
    }

    pub fn set_soa_minimum(&mut self, active: bool) {
        if active {
            self.0 |= 2;
        } else {
            self.0 &= !2;
        }
    }
}

impl TryFrom<u16> for Flags {
    type Error = DnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value & 0xFFFC != 0 {
            return Err(DnsError::InvalidCsyncFlag(value));
        }
        Ok(Self(value))
    }
}

impl From<Flags> for u16 {
    fn from(algorithm: Flags) -> Self {
        algorithm.0
    }
}
