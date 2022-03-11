mod dns;
mod util;

use std::net::SocketAddr;
use std::time::{Instant, Duration};
use net2::UdpBuilder;

use crate::util::ByteConvertible;

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
    let des = dns::Packet::from_network(&ser).unwrap();

    println!("[TEST] {:?} -> {:?}", query.header, des.header);
    println!("[TEST] {:?} -> {:?}", query.questions[0], des.questions[0]);
    // println!("[TEST] {}", query.questions[0].q_name);
}

pub fn discovery(record_name: &str, delay: &Duration) -> Result<Vec<MdnsResponse>, dns::DnsError> {
    // Prepare DNS query
    let dns_query = dns::Packet::with_question(1234, &dns::Question::with(record_name, 12, 1));

    let builder = UdpBuilder::new_v4().unwrap();
    builder.reuse_address(true).unwrap();
    let sock = builder.bind("0.0.0.0:5353").unwrap();
    sock.set_read_timeout(Some(*delay)).unwrap();

    // Test
    // test(&dns_query);

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

                let res = MdnsResponse { peer , packet: dns::Packet::from_network(&response_buffer[..size])? };

                for rec in res.packet.records.iter() {
                    println!("[DEBUG] {:?}", rec.get_data());
                }

                responses.push(res);
            },
            Err(e) => println!("ERROR {:?}", e)
        }
    }

    // println!("[RECEIVED] {:?}", responses[0].questions[0]);
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
            Err(_) => println!("Found nothing..."),
        }
    }
}
