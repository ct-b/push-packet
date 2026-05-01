mod color;
mod display;
mod packet;
mod tui;

use std::{
    collections::{HashMap, VecDeque},
    fmt::Display,
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::mpsc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use push_packet::{
    CopyConfig, Tap,
    rules::{Action, Rule},
};
use push_packet_common::FrameKind;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use crate::{
    color::{fade, ip_color, text_color},
    display::{format_bytes, format_cells},
    packet::{ingest_packet, parse_packet},
    tui::{Command, poll_input},
};

// CLI Args
#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long)]
    interface: String,
    #[arg(short, long, default_value_t = 10)]
    window: usize,
    #[arg(short, long)]
    nickname: Option<String>,
    #[arg(short, long)]
    mask: bool,
}

pub struct State {
    packet_info: HashMap<IpAddr, PacketInfo>,
    parse_failures: usize,
    max_ip_bytes: usize,
    mask_seed: Option<u64>,
    scroll: usize,
    show_stale: bool,
    show_log: bool,
    log: VecDeque<(Instant, String)>,
}

const LOG_CAPACITY: usize = 200;

impl State {
    fn new(mask: bool) -> Self {
        let mask_seed = mask.then(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        });
        Self {
            packet_info: HashMap::new(),
            parse_failures: 0,
            max_ip_bytes: 0,
            mask_seed,
            scroll: 0,
            show_stale: true,
            show_log: false,
            log: VecDeque::new(),
        }
    }
}

fn mask_ip(seed: u64, addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => {
            let mut hasher = DefaultHasher::new();
            (seed, addr).hash(&mut hasher);
            let bytes = hasher.finish().to_le_bytes();
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        }
        IpAddr::V6(_) => {
            let mut hi = DefaultHasher::new();
            (seed, addr, 0u8).hash(&mut hi);
            let mut lo = DefaultHasher::new();
            (seed, addr, 1u8).hash(&mut lo);
            let mut out = [0u8; 16];
            out[..8].copy_from_slice(&hi.finish().to_le_bytes());
            out[8..].copy_from_slice(&lo.finish().to_le_bytes());
            IpAddr::V6(Ipv6Addr::from(out))
        }
    }
}

// Last packet sent to an ip
#[derive(Clone, Copy)]
pub struct LastPacket {
    source_port: Option<u16>,
    dest_port: Option<u16>,
    proto: Proto,
    size: usize,
    source_addr: IpAddr,
    #[allow(dead_code)]
    dest_addr: IpAddr,
    arrived_at: Instant,
}

// Information about an IP
pub struct PacketInfo {
    base_color: Color,
    display_addr: IpAddr,
    total_packets: usize,
    tcp_bytes: usize,
    udp_bytes: usize,
    icmp_bytes: usize,
    total_bytes: usize,
    last: LastPacket,
    sizes: VecDeque<(Instant, usize)>,
}

impl PacketInfo {
    fn new(last: LastPacket, mask_seed: Option<u64>) -> Self {
        let display_addr = match mask_seed {
            Some(seed) => mask_ip(seed, last.source_addr),
            None => last.source_addr,
        };
        let base_color = ip_color(&display_addr);
        Self {
            base_color,
            display_addr,
            last,
            total_packets: 0,
            tcp_bytes: 0,
            udp_bytes: 0,
            icmp_bytes: 0,
            total_bytes: 0,
            sizes: VecDeque::default(),
        }
    }
}

#[derive(Clone, Copy)]
enum Proto {
    Tcp,
    Udp,
    Icmp,
}

impl Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Icmp => "ICMP",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        };
        write!(f, "{s}")
    }
}

const FRAME_PACKET_LIMIT: usize = 1000;

enum Message {
    Packet(LastPacket),
    ParseFailed(String),
}

fn main() -> color_eyre::Result<()> {
    let Args {
        interface,
        window,
        nickname,
        mask,
    } = Args::parse();
    let mut state = State::new(mask);
    let title_label = nickname.clone().unwrap_or_else(|| interface.clone());
    color_eyre::install()?;
    let mut terminal = ratatui::init();
    terminal.clear()?;
    let (tx, rx) = mpsc::channel();

    let iface = interface.clone();
    // Start the tap on another thread.
    let _handle = std::thread::spawn(move || {
        // We need to set force_enabled=true on the copy config if we don't start it with rules.
        // This allows us to determine the header size based on the FrameKind for the take, which
        // allows us to copy only data we are interested in, regardless of whether the interface
        // uses eth or ip frames.
        let mut tap = Tap::builder(iface)?
            .copy_config(CopyConfig::default().force_enabled())
            .build()?;

        let is_ip_frame = matches!(tap.frame_kind(), FrameKind::Ip);

        let take = if is_ip_frame { 60 } else { 76 };
        // Copy headers from all ipv4 traffic
        tap.add_rule(Rule::source_cidr("0.0.0.0/0").action(Action::Copy { take: Some(take) }))?;
        // Copy headers from all ipv6 traffic
        tap.add_rule(Rule::source_cidr("::0/0").action(Action::Copy { take: Some(take) }))?;

        // Get a copy receiver, parse packets
        let mut copy_rx = tap.copy_receiver()?;

        while let Ok(packet) = copy_rx.recv() {
            match parse_packet(packet, is_ip_frame) {
                Err(msg) => tx.send(Message::ParseFailed(msg)).unwrap(),
                Ok(packet) => tx.send(Message::Packet(packet)).unwrap(),
            }
        }
        Ok::<(), push_packet::Error>(())
    });

    loop {
        for _ in 0..FRAME_PACKET_LIMIT {
            let Ok(message) = rx.try_recv() else {
                break;
            };

            match message {
                Message::ParseFailed(msg) => {
                    state.parse_failures += 1;
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
                        .or_insert_with(|| PacketInfo::new(packet, mask_seed));
                    ingest_packet(packet, entry);
                    state.max_ip_bytes = state.max_ip_bytes.max(entry.total_bytes);
                }
            }
        }

        let mut quit = false;
        for cmd in poll_input()? {
            match cmd {
                Command::Quit => quit = true,
                Command::Reset => state.packet_info.clear(),
                Command::ScrollUp => state.scroll = state.scroll.saturating_sub(1),
                Command::ScrollDown => state.scroll = state.scroll.saturating_add(1),
                Command::ToggleStale => state.show_stale = !state.show_stale,
                Command::ToggleLog => state.show_log = !state.show_log,
            }
        }
        if quit {
            break;
        }
        state.packet_info.values_mut().for_each(|pi| {
            pi.sizes.retain(|sz| {
                let elapsed = sz.0.elapsed().as_secs_f32();
                elapsed < window as f32
            });
        });

        terminal.draw(|frame| render(frame, &mut state, window, &title_label))?;
    }

    ratatui::restore();
    Ok(())
}

fn render(frame: &mut Frame, state: &mut State, window: usize, title_label: &str) {
    let [title, _gap1, main, _gap2, legend] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(100),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(format!("push-packet | histogram | {}", title_label), title);
    let stale_label = if state.show_stale { "hide" } else { "show" };
    frame.render_widget(
        Line::from(format!(
            "r: reset  s: {stale_label} stale  l: log  q: quit"
        ))
        .style(Style::default().fg(Color::DarkGray)),
        legend,
    );
    frame.render_widget(
        Line::from(format!("parse failures: {}", state.parse_failures))
            .style(Style::default().fg(Color::DarkGray))
            .right_aligned(),
        legend,
    );

    let window_sums = state
        .packet_info
        .values()
        .filter(|pi| !pi.sizes.is_empty())
        .map(|pi| pi.sizes.iter().map(|sz| sz.1).sum::<usize>())
        .collect::<Vec<_>>();
    let max_window_sum = window_sums.iter().copied().max().unwrap_or(1);

    let formatted = state
        .packet_info
        .values()
        .map(|packet_info| {
            let ports = match (packet_info.last.source_port, packet_info.last.dest_port) {
                (Some(s), Some(d)) => format!("{:>5}:{:<5}", s, d),
                _ => " ".repeat(11),
            };
            [
                format!("{}", packet_info.display_addr),
                format_bytes(packet_info.total_bytes).to_string(),
                format!("{} p", packet_info.total_packets),
                format!(
                    "[{:<4} {} {:>width$} B]",
                    format!("{}", packet_info.last.proto),
                    ports,
                    packet_info.last.size,
                    width = 6,
                ),
            ]
        })
        .collect::<Vec<_>>();

    let mut widths = vec![0, 0, 0, 0];
    formatted.iter().for_each(|cells| {
        widths[0] = widths[0].max(cells[0].len());
        widths[1] = widths[1].max(cells[1].len());
        widths[2] = widths[2].max(cells[2].len());
        widths[3] = widths[3].max(cells[3].len());
    });

    let scrollbar_area = main;
    let main = Rect {
        width: main.width.saturating_sub(2),
        ..main
    };

    let view_height = main.height as usize;
    let total = if state.show_stale {
        state.packet_info.len()
    } else {
        window_sums.len()
    };
    state.scroll = state.scroll.min(total.saturating_sub(view_height));
    let scroll = state.scroll;
    let visible_y = |i: usize| -> Option<u16> {
        let row = i.checked_sub(scroll)?;
        (row < view_height).then_some(main.y + row as u16)
    };

    let mut i = 0;
    for (cells, packet_info) in formatted.iter().zip(state.packet_info.values()) {
        if packet_info.sizes.is_empty() {
            continue;
        }
        if let Some(y) = visible_y(i) {
            let width =
                (window_sums[i] as f64 / max_window_sum as f64 * main.width as f64) as u16;

            let bg_color = fade(packet_info.base_color, packet_info.last.arrived_at, window);
            let color = text_color(bg_color);
            let bar_width = width.min(main.width);
            let bar = Rect {
                x: main.x,
                y,
                width: bar_width,
                height: 1,
            };
            frame.render_widget(Block::new().style(Style::default().bg(bg_color)), bar);

            let output = format_cells(cells, &widths, 2, main.width as usize);

            let full_rect = Rect {
                x: main.x,
                y,
                width: main.width,
                height: 1,
            };
            let on_bar = Rect {
                width: bar_width,
                ..full_rect
            };
            frame.render_widget(
                Line::from(output.clone()).style(Style::default().fg(packet_info.base_color)),
                full_rect,
            );
            frame.render_widget(Line::from(output).style(Style::default().fg(color)), on_bar);
        }
        i += 1;
    }

    let inactive_style = Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::ITALIC);
    for (cells, packet_info) in formatted.iter().zip(state.packet_info.values()) {
        if !packet_info.sizes.is_empty() {
            continue;
        }
        if !state.show_stale {
            break;
        }
        if let Some(y) = visible_y(i) {
            let output = format_cells(cells, &widths, 2, main.width as usize);
            let full_rect = Rect {
                x: main.x,
                y,
                width: main.width,
                height: 1,
            };
            frame.render_widget(Line::from(output).style(inactive_style), full_rect);
        }
        i += 1;
    }

    if total > view_height {
        let max_scroll = total - view_height;
        let mut sb_state = ScrollbarState::new(max_scroll + 1)
            .viewport_content_length(view_height)
            .position(scroll);
        let grey = Style::default().fg(Color::DarkGray);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .thumb_style(grey)
                .track_style(grey)
                .begin_style(grey)
                .end_style(grey),
            scrollbar_area,
            &mut sb_state,
        );
    }

    if state.show_log {
        render_log(frame, scrollbar_area, &state.log);
    }
}

fn render_log(frame: &mut Frame, area: Rect, log: &VecDeque<(Instant, String)>) {
    let popup = Rect {
        x: area.x + area.width / 10,
        y: area.y + area.height / 10,
        width: area.width.saturating_sub(area.width / 5).max(20),
        height: area.height.saturating_sub(area.height / 5).max(5),
    };
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" parse failures ({}) ", log.len()))
        .style(Style::default().fg(Color::DarkGray).bg(Color::Black));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let lines: Vec<_> = log
        .iter()
        .rev()
        .take(inner.height as usize)
        .map(|(at, msg)| format!("{:>3}s ago  {msg}", at.elapsed().as_secs()))
        .collect();
    for (i, text) in lines.iter().enumerate() {
        let row = Rect {
            x: inner.x,
            y: inner.y + i as u16,
            width: inner.width,
            height: 1,
        };
        frame.render_widget(
            Line::from(text.as_str()).style(Style::default().fg(Color::Gray)),
            row,
        );
    }
}
