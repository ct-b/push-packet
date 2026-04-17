use std::{collections::HashMap, net::IpAddr, sync::mpsc::Sender};

use etherparse::SlicedPacket;
use push_packet::{
    FrameKind, Tap,
    events::CopyEvent,
    rules::{Action, Rule},
};

fn get_ip_and_size(frame_kind: &FrameKind, event: &CopyEvent<'_>) -> Option<(IpAddr, u32)> {
    let packet = match frame_kind {
        FrameKind::Eth => SlicedPacket::from_ethernet(event.data()),
        FrameKind::Ip => SlicedPacket::from_ip(event.data()),
    };
    let packet = match packet {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to parse packet: {e}");
            return None;
        }
    };
    let Some(net) = packet.net else {
        eprintln!("no network layer in packet");
        return None;
    };
    match net {
        etherparse::NetSlice::Ipv4(ip) => {
            Some((IpAddr::from(ip.header().source_addr()), event.len()))
        }
        etherparse::NetSlice::Ipv6(ip) => {
            Some((IpAddr::from(ip.header().source_addr()), event.len()))
        }
        _ => {
            eprintln!("failed to parse net type");
            return None;
        }
    }
}

fn run_tap(
    interface_name: &'static str,
    tx: Sender<(&'static str, IpAddr, u32)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tap = Tap::new(interface_name)?.with_rule(
        Rule::builder()
            .source_cidr("0.0.0.0/0")
            .action(Action::Copy { take: None }),
    )?;

    tap.start()?;

    let frame_kind = tap.frame_kind();
    println!("Using frame: {:?}", frame_kind);

    let mut rx = tap.copy_rx()?;
    while let Some(event) = rx.recv() {
        let Some((addr, len)) = get_ip_and_size(&frame_kind, &event) else {
            continue;
        };
        tx.send((interface_name, addr, len)).unwrap();
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx_1, rx) = std::sync::mpsc::channel();
    let tx_2 = tx_1.clone();

    std::thread::spawn(move || {
        run_tap("protonlaptop", tx_1).unwrap();
    });

    std::thread::spawn(move || {
        run_tap("wlp3s0", tx_2).unwrap();
    });

    let mut map = HashMap::new();

    while let Ok((name, addr, len)) = rx.recv() {
        *map.entry(name)
            .or_insert_with(HashMap::new)
            .entry(addr)
            .or_insert(0) += len;
        map.iter().for_each(|(name, data)| {
            println!("Name: {}", name);
            data.iter().for_each(|(ip, total)| {
                println!("  IP: {}, total: {}", ip, total);
            });
            println!();
        });
    }

    Ok(())
}
