use std::net::{Ipv4Addr, Ipv6Addr};
use ipnet::IpSub;
use clap::{App, Arg};
use std::io::{BufRead, BufReader};
use std::os::unix::net::{UnixStream,UnixListener};
use std::thread;
#[macro_use]
extern crate log;
extern crate env_logger;

enum NeighborType {
    Cust,
    Peer,
    Prov
}

struct Neighbor {
    ip: Ipv4Addr,
    n_type: NeighborType,
}

fn main() {
    env_logger::init();
    info!("Logger active.");

    let mut neighbors: Vec<Neighbor> = Vec::new();

    let args = App::new("CS3700 Project 2")
    .author("Nelson Chan <chan.chak@husky.neu.edu>")
    .arg(
        Arg::with_name("neighbors")
        .index(1)
        .required(true)
        .multiple(true)
        .help("The peers of this router"),
    )
    .get_matches();

    let arg_neighbors: Vec<_> = args.values_of("neighbors").unwrap().collect();
    for nei in arg_neighbors {
        let loc = nei.find('-').expect("Error finding the IP address of neighbor.");
        debug!("Got neighbor: ip:{}, type:{}", &nei[..loc], &nei[loc+1..]);
        let nei_type = match &nei[loc+1..] {
            "cust" => NeighborType::Cust,
            "peer" => NeighborType::Peer,
            "prov" => NeighborType::Prov,
            _ => panic!("Unexpected neighbor type!")
        };
        neighbors.push(Neighbor { ip: nei[..loc].parse().expect("Error parsing IP address of neighbor."), n_type: nei_type});
    }
}
