pub mod dns;
pub mod mdns;
mod util;

#[macro_use]
extern crate bitfield;

#[cfg(test)]
mod tests {
    use super::*;

    // TODO Implement proper unit tests for the dns submodule as well

    #[test]
    fn discovery_test() {
        let responses = mdns::discovery("_googlecast._tcp.local", &std::time::Duration::from_millis(500));
        println!("Found something! -- Number of received responses: {}", responses.len());
        for res in responses.iter() {
            if let Some(packet) = &res.packet {
                let serialized = packet.to_bytes();
                assert_eq!(serialized.len(), packet.byte_size());

                let desrerialized = dns::Packet::try_from(&serialized[..]).expect("Parsing failed");
                let desrerialized_serialized = desrerialized.to_bytes();
                assert_eq!(serialized.len(), desrerialized_serialized.len());
                for idx in 0..serialized.len() {
                    assert_eq!(serialized[idx], desrerialized_serialized[idx]);
                }

                let compressed = packet.to_bytes_compressed();
                let compressed_deserialized = dns::Packet::try_from(&compressed[..]).expect("Failed to parse");
                let compressed_uncompressed = compressed_deserialized.to_bytes();

                assert_eq!(compressed_deserialized.byte_size(), packet.byte_size());
                for idx in 0..serialized.len() {
                    assert_eq!(serialized[idx], compressed_uncompressed[idx]);
                }
            } else {
                println!("Error: {:?}", &res.error);
            }
        }
    }
}
