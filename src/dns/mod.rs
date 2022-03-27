mod packet;
mod question;
mod header;
mod record;
mod fqdn;
mod error;
mod util;

pub use self::packet::Packet;
pub use self::question::Question;
pub use self::record::{RecordClass, RecordType, RecordData, ResourceRecord};
pub use self::fqdn::FQDN;
pub use self::error::DnsError;

pub(super) const COMPRESSION_MASK: u8 = 0b1100_0000;
pub(super) const COMPRESSION_MASK_U16: u16 = 0b1100_0000_0000_0000;
