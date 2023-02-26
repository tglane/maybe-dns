use net2::UdpBuilder;
use std::collections::VecDeque;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::Response;
use crate::dns::{Packet, QClass, QType, Question};

const QUERY_IP: &str = "224.0.0.251";
const QUERY_PORT: u16 = 5353;

pub struct Resolver {
    sock: Arc<UdpSocket>,
    responses: Arc<Mutex<VecDeque<Response>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Resolver {
    fn drop(&mut self) {
        // Make sure the handle thread is joined before going out of scope
        if let Some(joinable) = self.handle.take() {
            joinable.join().unwrap();
        }
    }
}

impl Resolver {
    pub fn new() -> Self {
        let builder = UdpBuilder::new_v4().expect("[Error] Socket creation failed");
        builder
            .reuse_address(true)
            .expect("[ERROR] Socket configuration failed");

        Self {
            sock: Arc::new(
                builder
                    .bind(format!("0.0.0.0:{}", QUERY_PORT))
                    .expect("[ERROR] Socket binding failed"),
            ),
            responses: Arc::new(Mutex::new(VecDeque::new())),
            handle: None,
        }
    }

    pub fn start_discover(&mut self, record_name: &str, duration: Duration) {
        // Shared pointer to resources used in separate thread
        let responses = self.responses.clone();
        let socket = self.sock.clone();
        let record_name = record_name.to_string();

        let handle = std::thread::spawn(move || {
            socket
                .set_read_timeout(Some(duration))
                .expect("[ERROR] Socket configuration failed");

            // Prepare DNS query
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let packet_id: u16 = rng.gen();
            let dns_query = Packet::with_question(
                packet_id,
                false,
                Question::with(&record_name, QType::PTR, QClass::IN),
            );

            // Send binary and wait for answers
            socket
                .send_to(
                    &dns_query.to_bytes(),
                    format!("{}:{}", QUERY_IP, QUERY_PORT),
                )
                .unwrap();

            let discovery_start = Instant::now();
            while discovery_start.elapsed() <= duration {
                // Parse struct Response from buffer
                let mut buffer = [0_u8; 2048];
                match socket.recv_from(&mut buffer) {
                    Ok((size, peer)) => match Packet::try_from(&buffer[..size]) {
                        Ok(packet) => {
                            if packet.header.id != packet_id {
                                match responses.lock() {
                                    Ok(mut guarded_access) => {
                                        guarded_access.push_back(Response::with(peer, Ok(packet)))
                                    }
                                    Err(_) => (),
                                }
                            }
                        }
                        Err(err) => match responses.lock() {
                            Ok(mut guarded_access) => {
                                guarded_access.push_back(Response::with(peer, Err(err)))
                            }
                            Err(_) => (),
                        },
                    },
                    Err(_) => (),
                }
            }
        });
        self.handle = Some(handle);
    }

    pub fn responses_raw(&self) -> Arc<Mutex<VecDeque<Response>>> {
        self.responses.clone()
    }

    pub fn wait(&mut self) {
        if let Some(joinable) = self.handle.take() {
            joinable.join().unwrap();
        }
    }

    pub fn is_empty(&self) -> bool {
        match self.responses.lock() {
            Ok(guarded_access) => guarded_access.is_empty(),
            Err(_) => true,
        }
    }

    pub fn len(&self) -> usize {
        match self.responses.lock() {
            Ok(guarded_access) => guarded_access.len(),
            Err(_) => 0,
        }
    }

    pub fn consume_next(&mut self) -> Option<Response> {
        match self.responses.lock() {
            Ok(mut guarded_access) => guarded_access.pop_front(),
            Err(_) => None,
        }
    }
}
