pub mod oneshot;
pub mod resolver;

use std::net::SocketAddr;

use crate::dns::{Packet, DnsError};

pub use resolver::Resolver;

pub struct Response {
    pub peer: SocketAddr,
    pub result: Result<Packet, DnsError>,
}

impl Response {
    fn with(peer: SocketAddr, result: Result<Packet, DnsError>) -> Self {
        Self { peer, result }
    }
}
