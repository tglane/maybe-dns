pub mod dns;
pub mod util;

use std::net::SocketAddr;
use std::time::{Instant, Duration};
use net2::UdpBuilder;

#[macro_use]
extern crate bitfield;

const QUERY_IP: &str = "224.0.0.251";
const QUERY_PORT: u16 = 5353;

pub struct MdnsResponse {
    pub peer: SocketAddr,
    pub packet: dns::Packet,
}

fn test(query: &dns::Packet) {
    let ser = query.to_bytes();
    let des = dns::Packet::try_from(&ser[..]).unwrap();

    println!("[HEADER] {:?} -> {:?}", query.header, des.header);
    for rec in query.records.iter() {
        println!("[RECORD] {:?}", rec.rdata);
    }
    println!("---------------------------------------------------------\n");
    for rec in des.records.iter() {
        println!("[Check RECORD] {:?}", rec.rdata);
    }
    println!("=========================================================\n\n");

    let des_ser = des.to_bytes();
    assert_eq!(ser.len(), des_ser.len());
    for idx in 0..des_ser.len() {
        assert_eq!(ser[idx], des_ser[idx]);
    }

    let compressed = query.to_bytes_compressed();
    let compressed_parsed = dns::Packet::try_from(&compressed[..]).unwrap();
    println!("Unco: {:?}", des.records);
    println!("Comp: {:?}", compressed_parsed.records);
    println!("=========================================================\n\n");
}

pub fn discovery(record_name: &str, delay: &Duration) -> Result<Vec<MdnsResponse>, dns::DnsError> {
    // Prepare DNS query
    let dns_query = dns::Packet::with_question(1234, &dns::Question::with(record_name, dns::RecordType::PTR, dns::RecordClass::IN));

    let builder = UdpBuilder::new_v4().unwrap();
    builder.reuse_address(true).unwrap();
    let sock = builder.bind("0.0.0.0:5353").unwrap();
    sock.set_read_timeout(Some(*delay)).unwrap();

    // Send binary and wait for answers
    sock.send_to(&dns_query.to_bytes(), format!("{}:{}", QUERY_IP, QUERY_PORT)).unwrap();

    let mut responses = Vec::<MdnsResponse>::new();

    let discovery_start = Instant::now();
    while discovery_start.elapsed() <= *delay {
        println!("Waiting..");
        // Parse struct QueryResponse from response_buffer
        let mut response_buffer = [0_u8; 2048];
        match sock.recv_from(&mut response_buffer) {
            Ok((size, peer)) => {
                println!("Received {} bytes from {:?}", size, peer);

                let packet = dns::Packet::try_from(&response_buffer[..size])?;

                // Test parsing of larger packet
                test(&packet);

                responses.push(MdnsResponse { peer, packet });
            },
            Err(e) => println!("ERROR {:?}", e)
        }
    }

    Ok(responses)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO Implement proper unit tests

    #[test]
    fn discovery_test() {
        let res = discovery("_googlecast._tcp.local", &Duration::from_millis(500));
        match res {
            Ok(res_vec) => {
                println!("Found somethin! -- Number of responses: {}", res_vec.len());
            }
            Err(err) => println!("Found nothing... {:?}", err),
        }
    }
}
