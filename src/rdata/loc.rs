use std::convert::TryFrom;

use crate::buffer::DnsBuffer;
use crate::byteconvertible::ByteConvertible;
use crate::error::DnsError;
use crate::rdata::{RData, RecordData, RecordType};

/// The location record (LOC) describes a mechanism to allow the DNS to carry
/// location information about hosts, networks, and subnets.  Such information
/// for a small subset of hosts is currently contained in the flat-file UUCP
/// maps.  However, just as the DNS replaced the use of HOSTS.TXT to
/// carry host and network address information, it is possible to replace
/// the UUCP maps as carriers of location information.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Loc {
    /// Version number of the representation.  This must be zero.
    /// Implementations are required to check this field and make
    /// no assumptions about the format of unrecognized versions.
    pub version: u8,

    /// The diameter of a sphere enclosing the described entity, in
    /// centimeters, expressed as a pair of four-bit unsigned
    /// integers, each ranging from zero to nine, with the most
    /// significant four bits representing the base and the second
    /// number representing the power of ten by which to multiply
    /// the base.  This allows sizes from 0e0 (<1cm) to 9e9
    /// (90,000km) to be expressed.  This representation was chosen
    /// such that the hexadecimal representation can be read by
    /// eye; 0x15 = 1e5.  Four-bit values greater than 9 are
    /// undefined, as are values with a base of zero and a non-zero
    /// exponent.
    pub size: u8,

    /// The horizontal precision of the data, in centimeters,
    /// expressed using the same representation as SIZE.  This is
    /// the diameter of the horizontal "circle of error", rather
    /// than a "plus or minus" value.  (This was chosen to match
    /// the interpretation of SIZE; to get a "plus or minus" value,
    /// divide by 2.)
    pub horiz_pre: u8,

    /// The vertical precision of the data, in centimeters,
    /// expressed using the sane representation as for SIZE.  This
    /// is the total potential vertical error, rather than a "plus
    /// or minus" value.  (This was chosen to match the
    /// interpretation of SIZE; to get a "plus or minus" value,
    /// divide by 2.)  Note that if altitude above or below sea
    /// level is used as an approximation for altitude relative to
    /// the [WGS 84] ellipsoid, the precision value should be
    /// adjusted.
    pub vert_pre: u8,

    /// The latitude of the center of the sphere described by the
    /// SIZE field, expressed as a 32-bit integer, most significant
    /// octet first (network standard byte order), in thousandths
    /// of a second of arc.  2^31 represents the equator; numbers
    /// above that are north latitude.
    pub latitude: u32,

    /// The longitude of the center of the sphere described by the
    /// SIZE field, expressed as a 32-bit integer, most significant
    /// octet first (network standard byte order), in thousandths
    /// of a second of arc, rounded away from the prime meridian.
    /// 2^31 represents the prime meridian; numbers above that are
    /// east longitude.
    pub longitude: u32,

    /// The altitude of the center of the sphere described by the
    /// SIZE field, expressed as a 32-bit integer, most significant
    /// octet first (network standard byte order), in centimeters,
    /// from a base of 100,000m below the [WGS 84] reference
    /// spheroid used by GPS (semimajor axis a=6378137.0,
    /// reciprocal flattening rf=298.257223563).  Altitude above
    /// (or below) sea level may be used as an approximation of
    /// altitude relative to the the [WGS 84] spheroid, though due
    /// to the Earth's surface not being a perfect spheroid, there
    /// will be differences.  (For example, the geoid (which sea
    /// level approximates) for the continental US ranges from 10
    /// meters to 50 meters below the [WGS 84] spheroid.
    /// Adjustments to ALTITUDE and/or VERT PRE will be necessary
    /// in most cases.  The Defense Mapping Agency publishes geoid
    /// height values relative to the [WGS 84] ellipsoid.
    pub altitude: u32,
}

impl<'a> TryFrom<&mut DnsBuffer<'a>> for Loc {
    type Error = DnsError;

    fn try_from(buffer: &mut DnsBuffer<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            version: buffer.extract_u8()?,
            size: buffer.extract_u8()?,
            horiz_pre: buffer.extract_u8()?,
            vert_pre: buffer.extract_u8()?,
            latitude: buffer.extract_u32()?,
            longitude: buffer.extract_u32()?,
            altitude: buffer.extract_u32()?,
        })
    }
}

impl RData for Loc {
    fn record_type(&self) -> RecordType {
        RecordType::LOC
    }

    fn into_record_data(self) -> RecordData {
        RecordData::LOC(self)
    }
}

impl ByteConvertible for Loc {
    fn byte_size(&self) -> usize {
        16
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(16);
        buffer.push(self.version);
        buffer.push(self.size);
        buffer.push(self.horiz_pre);
        buffer.push(self.vert_pre);
        buffer.extend_from_slice(&u32::to_be_bytes(self.latitude));
        buffer.extend_from_slice(&u32::to_be_bytes(self.longitude));
        buffer.extend_from_slice(&u32::to_be_bytes(self.altitude));
        buffer
    }
}
