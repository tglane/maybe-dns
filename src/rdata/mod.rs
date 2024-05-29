mod a;
mod aaaa;
mod apl;
mod caa;
mod cname;
mod csync;
pub mod dhcid;
#[cfg(feature = "dnssec")]
mod dnssec;
mod eui48;
mod eui64;
mod hinfo;
mod hip;
pub mod ipseckey;
mod loc;
mod minfo;
mod mx;
pub mod naptr;
mod ns;
mod null;
mod openpgpkey;
mod opt;
mod ptr;
mod soa;
mod srv;
pub mod sshfp;
mod svcb;
pub mod tkey;
pub mod tlsa;
pub mod tsig;
mod txt;
mod uri;
mod wks;

use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::{ByteConvertible, CompressedByteConvertible};
use crate::error::DnsError;
use crate::resource::RecordType;

pub use self::a::A;
pub use self::aaaa::Aaaa;
pub use self::apl::Apl;
pub use self::caa::Caa;
pub use self::cname::Cname;
pub use self::csync::Csync;
pub use self::dhcid::Dhcid;
#[cfg(feature = "dnssec")]
pub use self::dnssec::{DnsKey, Ds, Nsec, Rrsig};
pub use self::eui48::Eui48;
pub use self::eui64::Eui64;
pub use self::hinfo::Hinfo;
pub use self::hip::Hip;
pub use self::ipseckey::IpSecKey;
pub use self::loc::Loc;
pub use self::minfo::Minfo;
pub use self::mx::Mx;
pub use self::naptr::Naptr;
pub use self::ns::Ns;
pub use self::null::Null;
pub use self::openpgpkey::OpenPgpKey;
pub use self::opt::Opt;
pub use self::ptr::Ptr;
pub use self::soa::Soa;
pub use self::srv::Srv;
pub use self::sshfp::Sshfp;
pub use self::svcb::Svcb;
pub use self::tkey::Tkey;
pub use self::tlsa::Tlsa;
pub use self::tsig::Tsig;
pub use self::txt::Txt;
pub use self::uri::Uri;
pub use self::wks::Wks;

pub trait RData {
    fn record_type(&self) -> RecordType;

    fn into_record_data(self) -> RecordData;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Reserved,
    RSA,
    DSA,
    ECDSA,
    Ed25519,
    Ed448,
}

impl TryFrom<u8> for Algorithm {
    type Error = DnsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::RSA),
            2 => Ok(Self::DSA),
            3 => Ok(Self::ECDSA),
            4 => Ok(Self::Ed25519),
            5 => Ok(Self::Ed448),
            _ => Err(DnsError::InvalidSSHFPAlgorithm(value)),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Reserved => 0,
            Algorithm::RSA => 1,
            Algorithm::DSA => 2,
            Algorithm::ECDSA => 3,
            Algorithm::Ed25519 => 4,
            Algorithm::Ed448 => 5,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordData {
    A(A),
    NS(Ns),
    CNAME(Cname),
    SOA(Soa),
    NULL(Null),
    WKS(Wks),
    PTR(Ptr),
    HINFO(Hinfo),
    MINFO(Minfo),
    MX(Mx),
    TXT(Txt),
    AAAA(Aaaa),
    LOC(Loc),
    SRV(Srv),
    NAPTR(Naptr),
    OPT(Opt),
    APL(Apl),
    #[cfg(feature = "dnssec")]
    DS(Ds),
    SSHFP(Sshfp),
    IPSECKEY(IpSecKey),
    #[cfg(feature = "dnssec")]
    RRSIG(Rrsig),
    #[cfg(feature = "dnssec")]
    NSEC(Nsec),
    #[cfg(feature = "dnssec")]
    DNSKEY(DnsKey),
    DHCID(Dhcid),
    TLSA(Tlsa),
    HIP(Hip),
    #[cfg(feature = "dnssec")]
    CDS(Ds),
    #[cfg(feature = "dnssec")]
    CDNSKEY(DnsKey),
    OPENPGPKEY(OpenPgpKey),
    CSYNC(Csync),
    SVCB(Svcb),
    EUI48(Eui48),
    EUI64(Eui64),
    TKEY(Tkey),
    TSIG(Tsig),
    URI(Uri),
    CAA(Caa),
}

impl RecordData {
    pub fn from(rec_type: RecordType, buffer: &mut DnsBuffer) -> Result<Self, DnsError> {
        Ok(match rec_type {
            RecordType::A => Self::A(A::try_from(buffer)?),
            RecordType::NS => Self::NS(Ns::try_from(buffer)?),
            RecordType::CNAME => Self::CNAME(Cname::try_from(buffer)?),
            RecordType::SOA => Self::SOA(Soa::try_from(buffer)?),
            RecordType::NULL => Self::NULL(Null::try_from(buffer)?),
            RecordType::WKS => Self::WKS(Wks::try_from(buffer)?),
            RecordType::PTR => Self::PTR(Ptr::try_from(buffer)?),
            RecordType::HINFO => Self::HINFO(Hinfo::try_from(buffer)?),
            RecordType::MINFO => Self::MINFO(Minfo::try_from(buffer)?),
            RecordType::MX => Self::MX(Mx::try_from(buffer)?),
            RecordType::TXT => Self::TXT(Txt::try_from(buffer)?),
            RecordType::AAAA => Self::AAAA(Aaaa::try_from(buffer)?),
            RecordType::LOC => Self::LOC(Loc::try_from(buffer)?),
            RecordType::SRV => Self::SRV(Srv::try_from(buffer)?),
            RecordType::NAPTR => Self::NAPTR(Naptr::try_from(buffer)?),
            RecordType::OPT => Self::OPT(Opt::try_from(buffer)?),
            RecordType::APL => Self::APL(Apl::try_from(buffer)?),
            #[cfg(feature = "dnssec")]
            RecordType::DS => Self::DS(Ds::try_from(buffer)?),
            RecordType::SSHFP => Self::SSHFP(Sshfp::try_from(buffer)?),
            RecordType::IPSECKEY => Self::IPSECKEY(IpSecKey::try_from(buffer)?),
            #[cfg(feature = "dnssec")]
            RecordType::RRSIG => Self::RRSIG(Rrsig::try_from(buffer)?),
            #[cfg(feature = "dnssec")]
            RecordType::NSEC => Self::NSEC(Nsec::try_from(buffer)?),
            #[cfg(feature = "dnssec")]
            RecordType::DNSKEY => Self::DNSKEY(DnsKey::try_from(buffer)?),
            RecordType::DHCID => Self::DHCID(Dhcid::try_from(buffer)?),
            RecordType::TLSA => Self::TLSA(Tlsa::try_from(buffer)?),
            RecordType::HIP => Self::HIP(Hip::try_from(buffer)?),
            #[cfg(feature = "dnssec")]
            RecordType::CDS => Self::CDS(Ds::try_from(buffer)?),
            #[cfg(feature = "dnssec")]
            RecordType::CDNSKEY => Self::CDNSKEY(DnsKey::try_from(buffer)?),
            RecordType::OPENPGPKEY => Self::OPENPGPKEY(OpenPgpKey::try_from(buffer)?),
            RecordType::CSYNC => Self::CSYNC(Csync::try_from(buffer)?),
            RecordType::SVCB => Self::SVCB(Svcb::try_from(buffer)?),
            RecordType::EUI48 => Self::EUI48(Eui48::try_from(buffer)?),
            RecordType::EUI64 => Self::EUI64(Eui64::try_from(buffer)?),
            RecordType::TKEY => Self::TKEY(Tkey::try_from(buffer)?),
            RecordType::TSIG => Self::TSIG(Tsig::try_from(buffer)?),
            RecordType::URI => Self::URI(Uri::try_from(buffer)?),
            RecordType::CAA => Self::CAA(Caa::try_from(buffer)?),
        })
    }
}

impl ByteConvertible for RecordData {
    fn byte_size(&self) -> usize {
        match self {
            Self::A(ref a) => a.byte_size(),
            Self::NS(ref name) => name.byte_size(),
            Self::CNAME(ref name) => name.byte_size(),
            Self::SOA(ref soa) => soa.byte_size(),
            Self::NULL(ref null) => null.byte_size(),
            Self::WKS(ref wks) => wks.byte_size(),
            Self::PTR(ref ptr) => ptr.byte_size(),
            Self::HINFO(ref hinfo) => hinfo.byte_size(),
            Self::MINFO(ref minfo) => minfo.byte_size(),
            Self::MX(ref mx) => mx.byte_size(),
            Self::TXT(ref txt) => txt.byte_size(),
            Self::AAAA(ref aaaa) => aaaa.byte_size(),
            Self::LOC(ref loc) => loc.byte_size(),
            Self::SRV(ref srv) => srv.byte_size(),
            Self::NAPTR(ref naptr) => naptr.byte_size(),
            Self::OPT(ref opt) => opt.byte_size(),
            Self::APL(ref apl) => apl.byte_size(),
            #[cfg(feature = "dnssec")]
            Self::DS(ref ds) => ds.byte_size(),
            Self::SSHFP(ref sshfp) => sshfp.byte_size(),
            Self::IPSECKEY(ref ipseckey) => ipseckey.byte_size(),
            #[cfg(feature = "dnssec")]
            Self::RRSIG(ref rrsig) => rrsig.byte_size(),
            #[cfg(feature = "dnssec")]
            Self::NSEC(ref nsec) => nsec.byte_size(),
            #[cfg(feature = "dnssec")]
            Self::DNSKEY(ref dnskey) => dnskey.byte_size(),
            Self::DHCID(ref dhcid) => dhcid.byte_size(),
            Self::TLSA(ref tlsa) => tlsa.byte_size(),
            Self::HIP(ref hip) => hip.byte_size(),
            #[cfg(feature = "dnssec")]
            Self::CDS(ref ds) => ds.byte_size(),
            #[cfg(feature = "dnssec")]
            Self::CDNSKEY(ref dnskey) => dnskey.byte_size(),
            Self::OPENPGPKEY(ref openpgpkey) => openpgpkey.byte_size(),
            Self::CSYNC(ref csync) => csync.byte_size(),
            Self::SVCB(ref svcb) => svcb.byte_size(),
            Self::EUI48(ref eui) => eui.byte_size(),
            Self::EUI64(ref eui) => eui.byte_size(),
            Self::TKEY(ref tkey) => tkey.byte_size(),
            Self::TSIG(ref tsig) => tsig.byte_size(),
            Self::URI(ref uri) => uri.byte_size(),
            Self::CAA(ref caa) => caa.byte_size(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::A(ref a) => a.to_bytes(),
            Self::NS(ref name) => name.to_bytes(),
            Self::CNAME(ref name) => name.to_bytes(),
            Self::SOA(ref soa) => soa.to_bytes(),
            Self::NULL(ref null) => null.to_bytes(),
            Self::WKS(ref wks) => wks.to_bytes(),
            Self::PTR(ref ptr) => ptr.to_bytes(),
            Self::HINFO(ref hinfo) => hinfo.to_bytes(),
            Self::MINFO(ref minfo) => minfo.to_bytes(),
            Self::MX(ref mx) => mx.to_bytes(),
            Self::TXT(ref txt) => txt.to_bytes(),
            Self::AAAA(ref aaaa) => aaaa.to_bytes(),
            Self::LOC(ref loc) => loc.to_bytes(),
            Self::SRV(ref srv) => srv.to_bytes(),
            Self::NAPTR(ref naptr) => naptr.to_bytes(),
            Self::OPT(opt) => opt.to_bytes(),
            Self::APL(ref apl) => apl.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::DS(ref ds) => ds.to_bytes(),
            Self::SSHFP(ref sshfp) => sshfp.to_bytes(),
            Self::IPSECKEY(ref ipseckey) => ipseckey.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::RRSIG(ref rrsig) => rrsig.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::NSEC(ref nsec) => nsec.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::DNSKEY(ref dnskey) => dnskey.to_bytes(),
            Self::DHCID(ref dhcid) => dhcid.to_bytes(),
            Self::TLSA(ref tlsa) => tlsa.to_bytes(),
            Self::HIP(ref hip) => hip.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::CDS(ref ds) => ds.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::CDNSKEY(ref dnskey) => dnskey.to_bytes(),
            Self::OPENPGPKEY(ref openpgpkey) => openpgpkey.to_bytes(),
            Self::CSYNC(ref csync) => csync.to_bytes(),
            Self::SVCB(ref svcb) => svcb.to_bytes(),
            Self::EUI48(ref eui) => eui.to_bytes(),
            Self::EUI64(ref eui) => eui.to_bytes(),
            Self::TKEY(ref tkey) => tkey.to_bytes(),
            Self::TSIG(ref tsig) => tsig.to_bytes(),
            Self::URI(ref uri) => uri.to_bytes(),
            Self::CAA(ref caa) => caa.to_bytes(),
        }
    }
}

impl CompressedByteConvertible for RecordData {
    fn to_bytes_compressed(
        &self,
        names: &mut std::collections::HashMap<u64, usize>,
        outer_off: usize,
    ) -> Vec<u8> {
        match self {
            Self::A(ref a) => a.to_bytes(),
            Self::NS(ref name) => name.to_bytes_compressed(names, outer_off),
            Self::CNAME(ref name) => name.to_bytes_compressed(names, outer_off),
            Self::SOA(ref soa) => soa.to_bytes_compressed(names, outer_off),
            Self::NULL(ref null) => null.to_bytes(),
            Self::WKS(ref wks) => wks.to_bytes(),
            Self::PTR(ref ptr) => ptr.to_bytes_compressed(names, outer_off),
            Self::HINFO(ref hinfo) => hinfo.to_bytes(),
            Self::MINFO(ref minfo) => minfo.to_bytes_compressed(names, outer_off),
            Self::MX(ref mx) => mx.to_bytes_compressed(names, outer_off),
            Self::TXT(ref txt) => txt.to_bytes(),
            Self::AAAA(ref aaaa) => aaaa.to_bytes(),
            Self::LOC(ref loc) => loc.to_bytes(),
            Self::SRV(ref srv) => srv.to_bytes_compressed(names, outer_off),
            Self::NAPTR(ref naptr) => naptr.to_bytes_compressed(names, outer_off),
            Self::OPT(opt) => opt.to_bytes(),
            Self::APL(ref apl) => apl.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::DS(ref ds) => ds.to_bytes(),
            Self::SSHFP(ref sshfp) => sshfp.to_bytes(),
            Self::IPSECKEY(ref ipseckey) => ipseckey.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::RRSIG(ref rrsig) => rrsig.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::NSEC(ref nsec) => nsec.to_bytes_compressed(names, outer_off),
            #[cfg(feature = "dnssec")]
            Self::DNSKEY(ref dnskey) => dnskey.to_bytes(),
            Self::DHCID(ref dhcid) => dhcid.to_bytes(),
            Self::TLSA(ref tlsa) => tlsa.to_bytes(),
            Self::HIP(ref hip) => hip.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::CDS(ref ds) => ds.to_bytes(),
            #[cfg(feature = "dnssec")]
            Self::CDNSKEY(ref dnskey) => dnskey.to_bytes(),
            Self::OPENPGPKEY(ref openpgpkey) => openpgpkey.to_bytes(),
            Self::CSYNC(ref csync) => csync.to_bytes(),
            Self::SVCB(ref svcb) => svcb.to_bytes(),
            Self::EUI48(ref eui) => eui.to_bytes(),
            Self::EUI64(ref eui) => eui.to_bytes(),
            Self::TKEY(ref tkey) => tkey.to_bytes(),
            Self::TSIG(ref tsig) => tsig.to_bytes(),
            Self::URI(ref uri) => uri.to_bytes(),
            Self::CAA(ref caa) => caa.to_bytes(),
        }
    }
}
