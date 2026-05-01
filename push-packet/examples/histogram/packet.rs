use std::{net::IpAddr, time::Instant};

use etherparse::LaxSlicedPacket;
use push_packet::events::copy::CopyEvent;

use crate::{LastPacket, PacketInfo, Proto};

// Ingest the last packet
pub fn ingest_packet(packet: LastPacket, entry: &mut PacketInfo) {
    entry.last = packet;
    entry.total_bytes += packet.size;
    entry.total_packets += 1;
    match packet.proto {
        Proto::Tcp => entry.tcp_bytes += packet.size,
        Proto::Udp => entry.udp_bytes += packet.size,
        Proto::Icmp => entry.icmp_bytes += packet.size,
    }
    entry.sizes.push_back((packet.arrived_at, packet.size));
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
