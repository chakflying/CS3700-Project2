use clap::{App, Arg};
use ipnet::IpSub;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::sync::mpsc;
#[macro_use]
extern crate log;
extern crate env_logger;

#[derive(Copy, Clone)]
enum NeighborType {
    Cust,
    Peer,
    Prov,
}

struct InitNeighbor {
    ip: Ipv4Addr,
    n_type: NeighborType,
}

struct Neighbor {
    ip: Ipv4Addr,
    n_type: NeighborType,
    listener: UnixListener,
}

impl InitNeighbor {
    fn connect(&self) -> Neighbor {
        Neighbor {
            ip: self.ip,
            n_type: self.n_type,
            listener: UnixListener::bind(self.ip.to_string())
                .expect(&format!("Erorr binding to Unix socket {}.", self.ip)),
        }
    }
}

impl Neighbor {
    fn listen(&self, tx: mpsc::Sender<String>) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    self.handle_message(stream, tx.clone());
                }
                Err(err) => {
                    error!("Error when receiving message from socket: {}", err);
                    break;
                }
            }
        }
    }

    fn handle_message(&self, stream: UnixStream, tx: mpsc::Sender<String>) {
        let stream = BufReader::new(stream);
        for line in stream.lines() {
            let output = line.unwrap();
            debug!("got message: {}", &output);
            tx.send(output).expect("Error sending message back to main thread.");
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
    for nei in neighbors {
        let new_tx = tx.clone();
        thread::spawn(move || {
            nei.listen(new_tx);
        });
    }

    for received in rx {
        println!("Got: {}", received);
    }
}
