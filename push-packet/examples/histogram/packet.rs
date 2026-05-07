use std::{
    collections::{HashMap, VecDeque},
    fmt::Display,
    net::IpAddr,
    time::Instant,
};

use etherparse::LaxSlicedPacket;
use push_packet::events::copy::CopyEvent;
use ratatui::style::Color;

use crate::{color::ip_color, display::format_bytes, mask};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Self::Icmp => "ICMP",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

#[derive(Clone, Copy)]
pub struct ProtoFilter {
    pub tcp: bool,
    pub udp: bool,
    pub icmp: bool,
}

impl ProtoFilter {
    pub fn has(&self, proto: Proto) -> bool {
        match proto {
            Proto::Tcp => self.tcp,
            Proto::Udp => self.udp,
            Proto::Icmp => self.icmp,
        }
    }
}

// Last packet sent to an ip
#[derive(Clone, Copy)]
pub struct LastPacket {
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub proto: Proto,
    pub size: usize,
    pub source_addr: IpAddr,
    #[allow(dead_code)]
    pub dest_addr: IpAddr,
    pub arrived_at: Instant,
}

// Information about an IP
pub struct PacketInfo {
    pub base_color: Color,
    pub display_addr: IpAddr,
    pub total_packets: usize,
    pub bytes: HashMap<Proto, usize>,
    pub last: HashMap<Proto, LastPacket>,
    pub sizes: VecDeque<(Instant, Proto, usize)>,
}

impl PacketInfo {
    pub fn new(source_addr: IpAddr, mask_seed: Option<u64>) -> Self {
        let display_addr = match mask_seed {
            Some(seed) => mask::mask_ip(seed, source_addr),
            None => source_addr,
        };
        Self {
            base_color: ip_color(&display_addr),
            display_addr,
            total_packets: 0,
            bytes: HashMap::new(),
            last: HashMap::new(),
            sizes: VecDeque::new(),
        }
    }

    pub fn last(&self, active: ProtoFilter) -> Option<LastPacket> {
        self.last
            .iter()
            .filter(|(p, _)| active.has(**p))
            .map(|(_, lp)| *lp)
            .max_by_key(|lp| lp.arrived_at)
    }

    pub fn cells(&self, active: ProtoFilter) -> [String; 4] {
        let total: usize = self
            .bytes
            .iter()
            .filter(|(p, _)| active.has(**p))
            .map(|(_, b)| *b)
            .sum();
        let last = self
            .last(active)
            .expect("cells called with active total > 0");
        let ports = if let (Some(s), Some(d)) = (last.source_port, last.dest_port) {
            format!("{:>5}:{:<5}", s, d)
        } else {
            " ".repeat(11)
        };
        [
            format!("{}", self.display_addr),
            format_bytes(total).to_string(),
            format!("{} p", self.total_packets),
            format!(
                "[{:<4} {} {:>width$} B]",
                last.proto,
                ports,
                last.size,
                width = 6
            ),
        ]
    }
}

// Ingest the last packet
pub fn ingest_packet(packet: LastPacket, entry: &mut PacketInfo) {
    entry.last.insert(packet.proto, packet);
    *entry.bytes.entry(packet.proto).or_insert(0) += packet.size;
    entry.total_packets += 1;
    entry
        .sizes
        .push_back((packet.arrived_at, packet.proto, packet.size));
}

// Parse the packet
pub fn parse_packet(packet: CopyEvent<'_>, is_ip_frame: bool) -> Result<LastPacket, String> {
    let arrived_at = Instant::now();
    let bytes = packet.data();
    let len = packet.packet_len();
    let packet = if is_ip_frame {
        LaxSlicedPacket::from_ip(bytes).map_err(|e| format!("ip slice ({len}B): {e}"))?
    } else {
        LaxSlicedPacket::from_ethernet(bytes).map_err(|e| format!("eth slice ({len}B): {e}"))?
    };
    let (source_addr, dest_addr): (IpAddr, IpAddr) = match packet.net {
        Some(etherparse::LaxNetSlice::Ipv4(v4)) => (
            v4.header().source_addr().into(),
            v4.header().destination_addr().into(),
        ),
        Some(etherparse::LaxNetSlice::Ipv6(v6)) => (
            v6.header().source_addr().into(),
            v6.header().destination_addr().into(),
        ),
        Some(etherparse::LaxNetSlice::Arp(_)) => return Err(format!("ARP packet ({len}B)")),
        None => return Err(format!("no IP layer ({len}B)")),
    };

    let (proto, source_port, dest_port): (Proto, Option<u16>, Option<u16>) = match packet.transport
    {
        Some(etherparse::TransportSlice::Udp(u)) => (
            Proto::Udp,
            u.source_port().into(),
            u.destination_port().into(),
        ),
        Some(etherparse::TransportSlice::Tcp(t)) => (
            Proto::Tcp,
            t.source_port().into(),
            t.destination_port().into(),
        ),
        Some(etherparse::TransportSlice::Icmpv4(_)) => (Proto::Icmp, None, None),
        Some(etherparse::TransportSlice::Icmpv6(_)) => (Proto::Icmp, None, None),
        None => return Err(format!("no transport layer ({source_addr} -> {dest_addr})")),
    };
    Ok(LastPacket {
        source_port,
        dest_port,
        source_addr,
        dest_addr,
        proto,
        size: len as usize,
        arrived_at,
    })
}
