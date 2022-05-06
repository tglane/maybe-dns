/// Module for parsing and creating DNS packets
pub mod dns;

/// Module contains resolver functions and structs for the mdns protocol
#[cfg(feature = "mdns")]
pub mod mdns;

mod util;
