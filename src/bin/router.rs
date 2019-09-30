use clap::{App, Arg};
use ipnet::{IpSub, Ipv4Net};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::{Result, Value};
use unix_socket::{UnixSeqpacket, UnixSeqpacketListener};

use std::fmt;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate unix_socket;

#[derive(PartialEq, Copy, Clone, Debug)]
enum NeighborType {
    Cust,
    Peer,
    Prov,
}

#[derive(PartialEq, Copy, Clone, Debug)]
enum BGPPacketType {
    Update,
    Revoke,
    Data,
    NoRoute,
    Dump,
    Table,
    Unknown,
}

#[derive(PartialEq, Debug, Serialize)]
enum RouteOrgin {
    IGP,
    EGP,
    UNK,
}

#[derive(Debug)]
struct Neighbor {
    ip: Ipv4Addr,
    n_type: NeighborType,
}

#[derive(Debug)]
struct NeighborStream {
    n_id: usize,
    ip: Ipv4Addr,
    stream: UnixSeqpacket,
}

#[derive(Clone, Debug)]
struct BGPPacket {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    p_type: BGPPacketType,
    msg: PacketMsg,
    neighbor: usize,
}

impl fmt::Display for BGPPacketType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            BGPPacketType::Update => "update",
            BGPPacketType::Revoke => "revoke",
            BGPPacketType::Data => "data",
            BGPPacketType::NoRoute => "no route",
            BGPPacketType::Dump => "dump",
            BGPPacketType::Table => "table",
            BGPPacketType::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
struct RouteInfo {
    neighbor: usize,
    net: Ipv4Net,
    localpref: String,
    selfOrigin: String,
    ASPath: Vec<String>,
    origin: RouteOrgin,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RouteInfoJson {
    network: Ipv4Addr,
    netmask: Ipv4Addr,
    peer: Ipv4Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct RouteUpdateInfoJson {
    network: Ipv4Addr,
    netmask: Ipv4Addr,
    localpref: String,
    selfOrigin: String,
    ASPath: Vec<String>,
    origin: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct MsgRevoke {
    network: Ipv4Addr,
    netmask: Ipv4Addr,
}

#[derive(Clone, Debug)]
enum PacketMsg {
    Update(RouteUpdateInfoJson),
    Revoke(Vec<MsgRevoke>),
    Data(String),
    Empty,
}

impl Neighbor {
    fn connect(&self, n_id: usize) -> NeighborStream {
        NeighborStream {
            n_id,
            ip: self.ip,
            stream: UnixSeqpacket::connect(self.ip.to_string())
                .expect(&format!("Error connecting to Unix socket {}.", self.ip)),
        }
    }
}

impl NeighborStream {
    fn set_timeout(&self) {
        self.stream
            .set_read_timeout(Some(Duration::new(0, 10000000)))
            .expect("Error setting read timeout.");
        self.stream
            .set_write_timeout(Some(Duration::new(1, 0)))
            .expect("Error setting write timeout.");
    }

    fn listen_and_send(&self, tx: mpsc::Sender<BGPPacket>, rx: mpsc::Receiver<String>) {
        loop {
            if let Ok(Some(err)) = self.stream.take_error() {
                error!("Got error: {:?}", err);
                break;
            }
            let mut buf = [0; 4096];
            let count = match self.stream.recv(&mut buf) {
                Ok(c) => c,
                Err(err) => {
                    // debug!("[{}] Recv error: {}", self.ip, err);
                    0
                }
            };
            if count > 0 {
                let s = String::from_utf8_lossy(&buf).to_string();
                debug!("[{}] Got message with length {}: {}", self.ip, count, s);

                let p: Value = match serde_json::from_str(&s[..count]) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("[{}] Error parsing packet: {}", self.ip, e);
                        Value::default()
                    }
                };
                let packet_type = match p["type"].as_str().unwrap() {
                    "data" => BGPPacketType::Data,
                    "update" => BGPPacketType::Update,
                    "revoke" => BGPPacketType::Revoke,
                    "no route" => BGPPacketType::NoRoute,
                    "dump" => BGPPacketType::Dump,
                    "table" => BGPPacketType::Table,
                    _ => BGPPacketType::Unknown,
                };
                let packet = BGPPacket {
                    src: p["src"]
                        .as_str()
                        .expect("Error getting src")
                        .parse()
                        .unwrap_or("0.0.0.0".parse().unwrap()),
                    dst: p["dst"]
                        .as_str()
                        .expect("Error getting dst")
                        .parse()
                        .unwrap_or("0.0.0.0".parse().unwrap()),
                    p_type: packet_type,
                    msg: match packet_type {
                        BGPPacketType::Data => {
                            PacketMsg::Data(p["msg"].as_str().unwrap().to_string())
                        }
                        BGPPacketType::Update => PacketMsg::Update(
                            serde_json::from_str(&p["msg"].to_string()[..]).expect("WHAT???"),
                        ),
                        BGPPacketType::Revoke => PacketMsg::Revoke(
                            serde_json::from_str(&p["msg"].to_string()[..]).expect("WHAT????"),
                        ),
                        BGPPacketType::NoRoute => PacketMsg::Empty,
                        BGPPacketType::Dump => PacketMsg::Empty,
                        _ => PacketMsg::Empty,
                    },
                    neighbor: self.n_id,
                };
                debug!("[{}] Parsed Packet: {:?}", self.ip, packet);
                tx.send(packet)
                    .expect("Error sending message back to main thread.");
            }
            // See if there is anything to send to this Neighbor
            match rx.try_recv() {
                Ok(msgjson) => {
                    debug!("[{}] Got message to send: {}", self.ip, msgjson);
                    self.stream
                        .send(msgjson.as_bytes())
                        .expect(&format!("[{}] Error when sending message", self.ip)[..]);
                }
                Err(_) => {} // Err(e) => debug!("[{}] Error when sending: {}", self.ip, e),
            }
        }
    }
}

fn choose_route(dst: Ipv4Addr, route_table: &Vec<RouteInfo>) -> i32 {
    let mut potential_routes = vec![];
    for (i, route) in route_table.iter().enumerate() {
        if route.net.contains(&dst) {
            potential_routes.push((i, route));
        }
    }
    debug!(
        "[Main Thread] choose_route found {} suitable routes for packet to {}",
        potential_routes.len(),
        dst
    );
    if potential_routes.len() == 1 {
        potential_routes[0].1.neighbor as i32
    } else if potential_routes.len() == 0 {
        -1
    } else {
        potential_routes[1].1.neighbor as i32
    }
}

fn main() {
    env_logger::init();
    info!("Logger active.");

    let (tx, rx) = mpsc::channel::<BGPPacket>();
    let mut neighbors: Vec<Neighbor> = Vec::new();
    let mut neighbors_streams: Vec<NeighborStream> = Vec::new();
    let mut neighbors_senders: Vec<mpsc::Sender<String>> = Vec::new();
    let mut route_table: Vec<RouteInfo> = Vec::new();
    let mut packet_history: Vec<BGPPacket> = Vec::new();

    // Declare the required arguments
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

    // Parse the arguments to obtain the neighbors and establish connection
    let arg_neighbors: Vec<_> = args.values_of("neighbors").unwrap().collect();
    for (i, nei) in arg_neighbors.iter().enumerate() {
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
        neighbors.push(Neighbor {
            ip: nei[..loc]
                .parse()
                .expect("Error parsing IP address of neighbor."),
            n_type: nei_type,
        });
        neighbors_streams.push(neighbors.last().unwrap().connect(i));
    }
    info!("Neighbors: {:?}", &neighbors);
    info!("Streams: {:?}", &neighbors_streams);

    // Start a new thread for each neighbor to listen for and send messages
    let mut threads = Vec::new();
    for nei in neighbors_streams {
        let new_tx = tx.clone();
        let (jtx, jrx) = mpsc::channel::<String>();
        neighbors_senders.push(jtx);
        threads.push(thread::spawn(move || {
            nei.set_timeout();
            debug!("[Main Thread] Spawning new thread for Neighbor {}", nei.ip);
            nei.listen_and_send(new_tx, jrx);
        }));
    }

    for received in rx {
        debug!(
            "[Main Thread] Got packet with type {} and dst {}",
            received.p_type, received.dst
        );
        packet_history.push(received.clone());

        // Process received packet according to its type
        match received.p_type {
            BGPPacketType::Update => {
                if received.dst != received.src.saturating_sub(1) {
                    continue;
                }
                match received.msg {
                    PacketMsg::Update(x) => {
                        let netmask: u32 = x.netmask.into();
                        let prefix: u8 = netmask.count_ones() as u8;
                        route_table.push(RouteInfo {
                            neighbor: received.neighbor,
                            net: Ipv4Net::new(x.network, prefix).unwrap(),
                            localpref: x.localpref.clone(),
                            selfOrigin: x.selfOrigin.clone(),
                            ASPath: x.ASPath.clone(),
                            origin: match x.origin.as_ref() {
                                "IGP" => RouteOrgin::IGP,
                                "EGP" => RouteOrgin::EGP,
                                "UNK" => RouteOrgin::UNK,
                                _ => RouteOrgin::UNK,
                            },
                        });

                        for (i, nei) in neighbors.iter().enumerate() {
                            if i == received.neighbor {
                                continue;
                            }
                            if neighbors[received.neighbor].n_type == NeighborType::Cust
                                || (neighbors[received.neighbor].n_type != NeighborType::Cust
                                    && nei.n_type == NeighborType::Cust)
                            {
                                debug!("[Main Thread] Forwarding update to neighbor [{}]", nei.ip);
                                neighbors_senders[i]
                                    .send(
                                        json!({
                                            "src": nei.ip.saturating_sub(1),
                                            "dst": nei.ip,
                                            "type": "update",
                                            "msg": {
                                                "network": x.network,
                                                "netmask": x.netmask,
                                                "localpref": x.localpref,
                                                "selfOrigin": x.selfOrigin,
                                                "ASPath": x.ASPath.clone(),
                                                "origin": x.origin,
                                            }
                                        })
                                        .to_string(),
                                    )
                                    .expect("Error sending message to other thread");
                            }
                        }
                    }
                    _ => {}
                };
            }
            BGPPacketType::Revoke => {}
            BGPPacketType::Data => match received.msg {
                PacketMsg::Data(msg) => {
                    let nei_no = choose_route(received.dst, &route_table);
                    if nei_no == -1
                        || (neighbors[nei_no as usize].n_type != NeighborType::Cust
                            && neighbors[received.neighbor].n_type != NeighborType::Cust)
                    {
                        debug!(
                            "[Main Thread] Reporting no route to neighbor [{}]",
                            &neighbors[received.neighbor].ip
                        );
                        neighbors_senders[received.neighbor]
                            .send(
                                json!({
                                    "src": neighbors[received.neighbor].ip.saturating_sub(1),
                                    "dst": received.src,
                                    "type": "no route",
                                    "msg": {},
                                })
                                .to_string(),
                            )
                            .expect("[Main Thread] Error sending message to other thread");
                    } else {
                        debug!(
                            "[Main Thread] Forwarding data to neighbor [{}]",
                            &neighbors[nei_no as usize].ip
                        );
                        neighbors_senders[nei_no as usize]
                            .send(
                                json!({
                                    "src": received.src,
                                    "dst": received.dst,
                                    "type": "data",
                                    "msg": msg,
                                })
                                .to_string(),
                            )
                            .expect("[Main Thread] Error sending message to other thread");
                    }
                }
                _ => {}
            },
            BGPPacketType::NoRoute => {}
            BGPPacketType::Dump => {
                let mut entries = vec![];
                for route in &route_table {
                    entries.push(RouteInfoJson {
                        network: route.net.addr(),
                        netmask: route.net.netmask(),
                        peer: neighbors[route.neighbor].ip,
                    });
                }
                neighbors_senders[received.neighbor]
                    .send(
                        json!({
                            "src": neighbors[received.neighbor].ip.saturating_sub(1),
                            "dst": received.src,
                            "type": "table",
                            "msg": entries,
                        })
                        .to_string(),
                    )
                    .expect("[Main Thread] Error sending message to other thread");
            }
            BGPPacketType::Table => {}
            BGPPacketType::Unknown => {}
        }
    }

    for thread in threads {
        thread.join().expect("Error waiting for thread to exit.");
    }
}
