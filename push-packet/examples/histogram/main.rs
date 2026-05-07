//! This example is a basic application of the library- a simple traffic monitor.
//! This shows how to tap into an interface, dynamically add and remove rules, and run a dedicated
//! parsing thread for reading packets and passing messages.
mod cli;
mod color;
mod display;
mod mask;
mod packet;
mod state;
mod tui;

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use clap::Parser;
use push_packet::{
    CopyConfig, Tap,
    rules::{Action, Protocol, Rule, RuleId},
};
use push_packet_common::FrameKind;

use crate::{
    cli::Args,
    packet::{LastPacket, PacketInfo, ingest_packet, parse_packet},
    state::State,
    tui::{Command, poll_input, render},
};

const LOG_CAPACITY: usize = 200;
const FRAME_PACKET_LIMIT: usize = 1000;

// Message passed from parser thread to main.
enum Message {
    Packet(LastPacket),
    ParseFailed(String),
}

fn main() -> color_eyre::Result<()> {
    let args = Args::parse();
    let title_label = args
        .nickname
        .clone()
        .unwrap_or_else(|| args.interface.clone());
    let mut state = State::new(&args);
    let frame_duration = Duration::from_millis(1000 / args.fps.max(1) as u64);
    color_eyre::install()?;

    // force_enabled=true on the copy config lets us start the tap with no rules
    // and add them later. Alternatively start the tap with a copy rule.
    let mut tap = Tap::builder(&args.interface)
        .copy_config(CopyConfig::default().force_enabled())
        .build()?;
    let is_ip_frame = matches!(tap.frame_kind(), FrameKind::Ip);

    let mut rule_ids: HashMap<(&'static str, Protocol), RuleId> = HashMap::new();
    let mut last_take = state.take;
    apply_rules(&mut tap, &mut rule_ids, &mut last_take, &state)?;

    // Create a dedicated parser thread that parses packets and sends messages.
    let copy_rx = tap.copy_receiver()?;
    let (tx, rx) = mpsc::channel::<Message>();
    let queue_depth = Arc::new(AtomicUsize::new(0));
    let parser_depth = queue_depth.clone();
    let parser = std::thread::spawn(move || -> Result<(), push_packet::Error> {
        let mut copy_rx = copy_rx;
        while let Ok(packet) = copy_rx.recv() {
            let msg = match parse_packet(packet, is_ip_frame) {
                Err(s) => Message::ParseFailed(s),
                Ok(p) => Message::Packet(p),
            };
            if tx.send(msg).is_err() {
                break;
            }
            parser_depth.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    });

    // All fallible lib setup is done. Enter TUI mode.
    let mut terminal = ratatui::init();
    terminal.clear()?;

    'outer: loop {
        if parser.is_finished() {
            break 'outer;
        }
        for _ in 0..FRAME_PACKET_LIMIT {
            let Ok(message) = rx.try_recv() else {
                break;
            };
            queue_depth.fetch_sub(1, Ordering::Relaxed);
            match message {
                Message::ParseFailed(msg) => {
                    if state.log.len() == LOG_CAPACITY {
                        state.log.pop_front();
                    }
                    state.log.push_back((Instant::now(), msg));
                }
                Message::Packet(packet) => {
                    let mask_seed = state.mask_seed;
                    let entry = state
                        .packet_info
                        .entry(packet.source_addr)
                        .or_insert_with(|| PacketInfo::new(packet.source_addr, mask_seed));
                    ingest_packet(packet, entry);
                }
            }
        }

        let mut filters_changed = false;
        for cmd in poll_input(frame_duration)? {
            match cmd {
                Command::Quit => break 'outer,
                Command::Reset => state.packet_info.clear(),
                Command::ScrollUp => state.scroll = state.scroll.saturating_sub(1),
                Command::ScrollDown => state.scroll = state.scroll.saturating_add(1),
                Command::ToggleStale => state.show_stale = !state.show_stale,
                Command::ToggleLog => state.show_log = !state.show_log,
                Command::ToggleTcp => {
                    state.show_tcp = !state.show_tcp;
                    filters_changed = true;
                }
                Command::ToggleUdp => {
                    state.show_udp = !state.show_udp;
                    filters_changed = true;
                }
                Command::ToggleIcmp => {
                    state.show_icmp = !state.show_icmp;
                    filters_changed = true;
                }
                Command::ToggleV4 => {
                    state.show_v4 = !state.show_v4;
                    filters_changed = true;
                }
                Command::ToggleV6 => {
                    state.show_v6 = !state.show_v6;
                    filters_changed = true;
                }
                Command::IncTake => {
                    state.take = state.take.saturating_add(10);
                    filters_changed = true;
                }
                Command::DecTake => {
                    state.take = state.take.saturating_sub(10).max(4);
                    filters_changed = true;
                }
            }
        }
        if filters_changed {
            apply_rules(&mut tap, &mut rule_ids, &mut last_take, &state)?;
        }

        state.packet_info.values_mut().for_each(|pi| {
            pi.sizes
                .retain(|sz| sz.0.elapsed().as_secs_f32() < args.window as f32);
        });

        let depth = queue_depth.load(Ordering::Relaxed);
        terminal.draw(|frame| render(frame, &mut state, args.window, &title_label, depth))?;
    }

    ratatui::restore();
    // Only join if the parser already exited (it died or hit an error). On a normal
    // quit it's still blocked in recv(); skip the join and let process exit reap it,
    // otherwise we'd hang waiting for the next packet to arrive.
    if parser.is_finished() {
        parser.join().unwrap()?;
    }
    Ok(())
}

// Add a copy rule and track its id keyed by (cidr, protocol).
fn add_copy_rule(
    tap: &mut Tap,
    rule_ids: &mut HashMap<(&'static str, Protocol), RuleId>,
    cidr: &'static str,
    proto: Protocol,
    take: u32,
) -> Result<(), push_packet::Error> {
    let rule_id = tap.add_rule(
        Rule::source_cidr(cidr)
            .protocol(proto)
            .action(Action::Copy { take: Some(take) }),
    )?;
    rule_ids.insert((cidr, proto), rule_id);
    Ok(())
}

// Update the existing rule set based on toggles and take.
fn apply_rules(
    tap: &mut Tap,
    rule_ids: &mut HashMap<(&'static str, Protocol), RuleId>,
    last_take: &mut u32,
    state: &State,
) -> Result<(), push_packet::Error> {
    // `take` is part of every rule's action, so a take change invalidates all of them.
    if state.take != *last_take {
        for (_, rule_id) in std::mem::take(rule_ids) {
            tap.remove_rule(rule_id)?;
        }
        *last_take = state.take;
    }

    let desired: [(bool, &'static str, Protocol); 6] = [
        (state.show_v4 && state.show_tcp, "0.0.0.0/0", Protocol::Tcp),
        (state.show_v4 && state.show_udp, "0.0.0.0/0", Protocol::Udp),
        (
            state.show_v4 && state.show_icmp,
            "0.0.0.0/0",
            Protocol::Icmp,
        ),
        (state.show_v6 && state.show_tcp, "::0/0", Protocol::Tcp),
        (state.show_v6 && state.show_udp, "::0/0", Protocol::Udp),
        (state.show_v6 && state.show_icmp, "::0/0", Protocol::Icmpv6),
    ];

    // Remove rules no longer needed.
    let stale: Vec<_> = rule_ids
        .keys()
        .copied()
        .filter(|key| {
            !desired
                .iter()
                .any(|(active, c, p)| *active && (*c, *p) == *key)
        })
        .collect();
    for key in stale {
        let rule_id = rule_ids.remove(&key).unwrap();
        tap.remove_rule(rule_id)?;
    }

    // Add rules now wanted that aren't already active.
    for &(active, cidr, proto) in &desired {
        if active && !rule_ids.contains_key(&(cidr, proto)) {
            add_copy_rule(tap, rule_ids, cidr, proto, state.take)?;
        }
    }

    Ok(())
}
