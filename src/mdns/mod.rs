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


#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::time::Duration;

    use super::*;

    #[test]
    fn oneshot_test() {
        // let responses = oneshot::discovery("_googlecast._tcp.local", &Duration::from_millis(500)).unwrap();
        let responses = oneshot::discover("_airplay._tcp.local", Duration::from_millis(500)).unwrap();
        // let responses = oneshot::discovery("lb._dns-sd._udp.local", &Duration::from_millis(500)).unwrap());
        println!("Discovery finished -- Number of received responses: {}", responses.len());
        for res in responses.iter() {
            if let Ok(packet) = &res.result {
                let serialized = packet.to_bytes();
                assert_eq!(serialized.len(), packet.byte_size());

                let desrerialized = Packet::try_from(&serialized[..]).expect("Parsing failed");
                let desrerialized_serialized = desrerialized.to_bytes();
                assert_eq!(serialized.len(), desrerialized_serialized.len());
                for idx in 0..serialized.len() {
                    assert_eq!(serialized[idx], desrerialized_serialized[idx]);
                }

                let compressed = packet.to_bytes_compressed();
                let compressed_deserialized = Packet::try_from(&compressed[..]).expect("Failed to parse");
                assert_eq!(compressed_deserialized.byte_size(), desrerialized.byte_size());
                let compressed_uncompressed = compressed_deserialized.to_bytes();

                assert_eq!(compressed_deserialized.byte_size(), packet.byte_size());
                for idx in 0..serialized.len() {
                    assert_eq!(serialized[idx], compressed_uncompressed[idx]);
                }
            }
        }
    }

    #[test]
    fn resolver_test() {
        let mut resolver = Resolver::new();
        resolver.start_discover("_airplay._tcp.local", Duration::from_millis(500));

        resolver.wait();

        for _ in 0..resolver.len() {
            println!("Resolve response: {}", resolver.consume_next().unwrap().peer);
        }
    }
}
