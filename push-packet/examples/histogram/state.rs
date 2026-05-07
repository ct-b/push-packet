use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    cli::Args,
    packet::{PacketInfo, ProtoFilter},
};

pub struct State {
    pub packet_info: HashMap<IpAddr, PacketInfo>,
    pub mask_seed: Option<u64>,
    pub scroll: usize,
    pub show_stale: bool,
    pub show_log: bool,
    pub show_tcp: bool,
    pub show_udp: bool,
    pub show_icmp: bool,
    pub show_v4: bool,
    pub show_v6: bool,
    pub take: u32,
    pub log: VecDeque<(Instant, String)>,
}

impl State {
    pub fn new(args: &Args) -> Self {
        let mask_seed = args.mask.then(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        });
        Self {
            packet_info: HashMap::new(),
            mask_seed,
            scroll: 0,
            show_stale: true,
            show_log: false,
            show_tcp: !args.no_tcp,
            show_udp: !args.no_udp,
            show_icmp: !args.no_icmp,
            show_v4: !args.no_v4,
            show_v6: !args.no_v6,
            take: 100,
            log: VecDeque::new(),
        }
    }

    pub fn proto_filter(&self) -> ProtoFilter {
        ProtoFilter {
            tcp: self.show_tcp,
            udp: self.show_udp,
            icmp: self.show_icmp,
        }
    }
}
