use std::convert::TryFrom;
use std::time::{Instant, Duration};
use net2::UdpBuilder;

use crate::dns::{Packet, Question, DnsError, QClass, QType};
use super::Response;


const QUERY_IP: &str = "224.0.0.251";
const QUERY_PORT: u16 = 5353;


pub fn discover(record_name: &str, delay: Duration) -> Result<Vec<Response>, DnsError> {
    // TODO Add options parameter (e.g. capture the query as response and more)
    // TODO Return first answer because a oneshot resolver just queries for one response

    // Prepare DNS query
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let packet_id: u16 = rng.gen();
    let dns_query = Packet::with_question(packet_id, false, &Question::with(record_name, QType::PTR, QClass::IN));

    // Init connection
    let builder = UdpBuilder::new_v4().expect("[Error] Socket creation failed");
    builder.reuse_address(true).expect("[ERROR] Socket configuration failed");
    let sock = builder.bind("0.0.0.0:5353").expect("[ERROR] Socket binding failed");
    sock.set_read_timeout(Some(delay)).expect("[ERROR] Socket configuration failed");

    // Send binary and wait for answers
    sock.send_to(&dns_query.to_bytes(), format!("{}:{}", QUERY_IP, QUERY_PORT)).unwrap();

    let mut responses = Vec::<Response>::new();

    let discovery_start = Instant::now();
    while discovery_start.elapsed() <= delay {
        // Parse struct Response from buffer
        let mut response_buffer = [0_u8; 2048];
        match sock.recv_from(&mut response_buffer) {
            Ok((size, peer)) => {
                match Packet::try_from(&response_buffer[..size]) {
                    Ok(packet) => {
                        if packet.header.id != packet_id {
                            responses.push(Response::with(peer, Ok(packet)));
                        }
                    },
                    Err(err) => {
                        responses.push(Response::with(peer, Err(err)));
                    },
                }
            },
            Err(_) => (),
        }
    }

    Ok(responses)
}
