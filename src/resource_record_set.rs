use crate::byteconvertible::ByteConvertible;
use crate::fqdn::FQDN;
use crate::rdata::RecordData;
use crate::resource::RecordClass;
use crate::resource::RecordType;

#[derive(Clone, Debug)]
pub struct ResourceRecordSet<'a> {
    name: &'a FQDN,
    set_type: RecordType,
    set_class: RecordClass,
    ttl: u32,
    records: Vec<&'a RecordData>,
}

impl<'a> ResourceRecordSet<'a> {
    pub fn new(
        name: &'a FQDN,
        set_type: RecordType,
        set_class: RecordClass,
        ttl: u32,
        records: Vec<&'a RecordData>,
    ) -> Self {
        Self {
            name,
            set_type,
            set_class,
            ttl,
            records,
        }
    }

    /// Reorders the records of the set to bring them in the canonical order
    /// This function is costly because it needs to create the wire format of all the records to
    /// identify the correct order
    pub fn canonical_reorder(&mut self) {
        self.records.sort_by_key(|a| a.to_bytes());
    }

    pub fn name(&self) -> &'a FQDN {
        self.name
    }

    pub fn set_type(&self) -> RecordType {
        self.set_type
    }

    pub fn set_class(&self) -> RecordClass {
        self.set_class
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn records(&self) -> &[&'a RecordData] {
        &self.records
    }
}

impl<'a> ByteConvertible for ResourceRecordSet<'a> {
    fn byte_size(&self) -> usize {
        self.records.iter().fold(0, |acc, rr| {
            acc + self.name.byte_size() + 10 + rr.byte_size()
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        // Preallocate size for the rrsig record and all records of the input set
        // signature = sign(RRSIG_RDATA | RR(1) | RR(2)... ) where
        //    "|" denotes concatenation;
        let mut binary_records = Vec::with_capacity(self.records.len());
        let name_bin = self.name.to_bytes();

        // RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        //    with the Signer's Name field in canonical form and
        //    the Signature field excluded;
        // RR(i) = owner | type | class | TTL | RDATA length | RDATA
        // Create canonical ordering of the record set
        let mut sig_size = 0;
        self.records.iter().for_each(|rr| {
            let bin = rr.to_bytes();
            let pos = binary_records
                .binary_search(&bin)
                .unwrap_or_else(|insert_pos| insert_pos);
            sig_size += name_bin.len() + 10 + bin.len();
            binary_records.insert(pos, bin);
        });

        // Extend signature data with ordered record set
        let mut binary = Vec::with_capacity(sig_size);
        for bin in binary_records {
            binary.extend_from_slice(&name_bin);
            binary.extend_from_slice(&u16::to_be_bytes(self.set_type.into()));
            binary.extend_from_slice(&u16::to_be_bytes(self.set_class.into()));
            binary.extend_from_slice(&u32::to_be_bytes(self.ttl));
            binary.extend_from_slice(&u16::to_be_bytes(bin.len() as u16));
            binary.extend_from_slice(&bin);
        }

        binary
    }
}
