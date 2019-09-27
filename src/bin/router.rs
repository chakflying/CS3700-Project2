use clap::{App, Arg};
use ipnet::IpSub;
use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use unix_socket::{UnixSeqpacket, UnixSeqpacketListener};

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate unix_socket;

#[derive(Copy, Clone)]
enum NeighborType {
    Cust,
    Peer,
    Prov,
}

#[derive(Debug)]
enum BGPPacketType {
    Update,
    Revoke,
    Data,
    NoRoute,
    Dump,
    Table,
    Unknown,
}

struct InitNeighbor {
    ip: Ipv4Addr,
    n_type: NeighborType,
}

struct Neighbor {
    ip: Ipv4Addr,
    n_type: NeighborType,
    stream: UnixSeqpacket,
}

#[derive(Debug)]
struct BGPPacket {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    p_type: BGPPacketType,
    msg: Value,
}

impl InitNeighbor {
    fn connect(&self) -> Neighbor {
        Neighbor {
            ip: self.ip,
            n_type: self.n_type,
            stream: UnixSeqpacket::connect(self.ip.to_string())
                .expect(&format!("Error connecting to Unix socket {}.", self.ip)),
        }
    }
}

impl Neighbor {
    fn set_timeout(&self) {
        self.stream
            .set_read_timeout(Some(Duration::new(1, 0)))
            .expect("Error setting read timeout.");
        self.stream
            .set_write_timeout(Some(Duration::new(1, 0)))
            .expect("Error setting write timeout.");
    }

    fn listen(&self, tx: mpsc::Sender<String>) {
        loop {
            if let Ok(Some(err)) = self.stream.take_error() {
                println!("Got error: {:?}", err);
                break;
            }
            let mut buf = [0; 4096];
            let mut totalcount = 0;
            loop {
                let count = match self.stream.recv(&mut buf) {
                    Ok(c) => {
                        totalcount += c;
                        c
                    }
                    Err(_err) => {
                        // info!("[{}] Recv error: {}",self.ip, err);
                        0
                    }
                };
                if count == 0 {
                    break;
                }
            }
            let s = String::from_utf8_lossy(&buf).to_string();
            if totalcount == 0 {
                continue;
            }
            debug!(
                "[{}] Got message with length {}: {}",
                self.ip, totalcount, s
            );
            tx.send(s[..totalcount].to_string())
                .expect("Error sending message back to main thread.");
        }
    }
}

fn main() {
    env_logger::init();
    info!("Logger active.");

    let (tx, rx) = mpsc::channel();
    let mut neighbors: Vec<Neighbor> = Vec::new();

    let args = App::new("CS3700 Project 2")
        .author("Nelson Chan <chan.chak@husky.neu.edu>")
        .arg(
            Arg::with_name("neighbors")
                .index(1)
                .required(true)
                .multiple(true)
                .help("The neighbors of this router"),
        )
        .get_matches();

    let arg_neighbors: Vec<_> = args.values_of("neighbors").unwrap().collect();
    for nei in arg_neighbors {
        let loc = nei
            .find('-')
            .expect("Error finding the IP address of neighbor.");
        debug!("Got neighbor: ip:{}, type:{}", &nei[..loc], &nei[loc + 1..]);
        let nei_type = match &nei[loc + 1..] {
            "cust" => NeighborType::Cust,
            "peer" => NeighborType::Peer,
            "prov" => NeighborType::Prov,
            _ => panic!("Unexpected neighbor type!"),
        };
        neighbors.push(
            InitNeighbor {
                ip: nei[..loc]
                    .parse()
                    .expect("Error parsing IP address of neighbor."),
                n_type: nei_type,
            }
            .connect(),
        );
    }
    let mut threads = Vec::new();
    for nei in neighbors {
        let new_tx = tx.clone();
        threads.push(thread::spawn(move || {
            nei.set_timeout();
            debug!("Spawning new thread for Neighbor {}", nei.ip);
            nei.listen(new_tx);
        }));
    }

    for received in rx {
        debug!("[Main Thread] Got packet with length {}", received.len());
        let p: Value = match serde_json::from_str(&received[..]) {
            Ok(p) => p,
            Err(e) => {
                error!("Error parsing received packet: {}", e);
                Value::default()
            }
        };
        let packet: BGPPacket = BGPPacket {
            src: p["src"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap_or("0.0.0.0".parse().unwrap()),
            dst: p["dst"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap_or("0.0.0.0".parse().unwrap()),
            p_type: match p["type"].as_str().unwrap() {
                "data" => BGPPacketType::Data,
                "update" => BGPPacketType::Update,
                "revoke" => BGPPacketType::Revoke,
                "no route" => BGPPacketType::NoRoute,
                "dump" => BGPPacketType::Dump,
                "table" => BGPPacketType::Table,
                _ => BGPPacketType::Unknown,
            },
            msg: p["msg"].clone(),
        };
        debug!("[Main Thread] Parsed Packet: {:?}", packet);
    }

    for thread in threads {
        thread.join().expect("Error waiting for thread to exit.");
    }
}
