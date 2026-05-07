use std::{
    borrow::Cow,
    collections::VecDeque,
    net::IpAddr,
    time::{Duration, Instant},
};

use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use crate::{
    color::{fade, text_color},
    display::format_cells,
    state::State,
};

pub enum Command {
    Quit,
    Reset,
    ScrollUp,
    ScrollDown,
    ToggleStale,
    ToggleLog,
    ToggleTcp,
    ToggleUdp,
    ToggleIcmp,
    ToggleV4,
    ToggleV6,
    IncTake,
    DecTake,
}

pub fn poll_input(timeout: Duration) -> color_eyre::Result<Vec<Command>> {
    let mut cmds = vec![];
    if !event::poll(timeout)? {
        return Ok(cmds);
    }
    loop {
        if let Event::Key(k) = event::read()? {
            let ctrl_c =
                k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
            if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                cmds.push(Command::Quit);
            } else if let KeyCode::Char('r') = k.code {
                cmds.push(Command::Reset);
            } else if let KeyCode::Char('s') = k.code {
                cmds.push(Command::ToggleStale);
            } else if let KeyCode::Char('l') = k.code {
                cmds.push(Command::ToggleLog);
            } else if let KeyCode::Char('t') = k.code {
                cmds.push(Command::ToggleTcp);
            } else if let KeyCode::Char('u') = k.code {
                cmds.push(Command::ToggleUdp);
            } else if let KeyCode::Char('i') = k.code {
                cmds.push(Command::ToggleIcmp);
            } else if let KeyCode::Char('4') = k.code {
                cmds.push(Command::ToggleV4);
            } else if let KeyCode::Char('6') = k.code {
                cmds.push(Command::ToggleV6);
            } else if matches!(k.code, KeyCode::Char('+') | KeyCode::Char('=')) {
                cmds.push(Command::IncTake);
            } else if let KeyCode::Char('-') = k.code {
                cmds.push(Command::DecTake);
            } else if matches!(k.code, KeyCode::Up) {
                cmds.push(Command::ScrollUp);
            } else if matches!(k.code, KeyCode::Down) {
                cmds.push(Command::ScrollDown);
            }
        }
        if !event::poll(Duration::from_millis(0))? {
            break;
        }
    }
    Ok(cmds)
}

struct EntryView {
    cells: [String; 4],
    base_color: Color,
    window_sum: usize,
    is_active: bool,
    last_arrived: Instant,
}

pub fn render(
    frame: &mut Frame,
    state: &mut State,
    window: usize,
    title_label: &str,
    queue_depth: usize,
) {
    let [title, _gap1, main, _gap2, legend] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(100),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(format!("push-packet | histogram | {}", title_label), title);
    frame.render_widget(
        Line::from(format!("queue: {queue_depth:>3}"))
            .style(Style::default().fg(Color::DarkGray))
            .right_aligned(),
        title,
    );

    frame.render_widget(legend_line(state), legend);
    frame.render_widget(filters_line(state).right_aligned(), legend);

    let active = state.proto_filter();
    let views: Vec<EntryView> = state
        .packet_info
        .values()
        .filter_map(|pi| {
            let family_on = match pi.display_addr {
                IpAddr::V4(_) => state.show_v4,
                IpAddr::V6(_) => state.show_v6,
            };
            if !family_on {
                return None;
            }
            let active_total: usize = pi
                .bytes
                .iter()
                .filter(|(p, _)| active.has(**p))
                .map(|(_, b)| *b)
                .sum();
            if active_total == 0 {
                return None;
            }
            let window_sum: usize = pi
                .sizes
                .iter()
                .filter(|(_, p, _)| active.has(*p))
                .map(|(_, _, s)| *s)
                .sum();
            let last_arrived = pi.last(active).expect("active total > 0").arrived_at;
            Some(EntryView {
                cells: pi.cells(active),
                base_color: pi.base_color,
                window_sum,
                is_active: window_sum > 0,
                last_arrived,
            })
        })
        .collect();

    let max_window_sum = views.iter().map(|v| v.window_sum).max().unwrap_or(1).max(1);

    let mut widths = [0usize; 4];
    for v in &views {
        for (slot, cell) in widths.iter_mut().zip(&v.cells) {
            *slot = (*slot).max(cell.len());
        }
    }

    let scrollbar_area = main;
    let main = Rect {
        width: main.width.saturating_sub(2),
        ..main
    };

    let view_height = main.height as usize;
    let active_count = views.iter().filter(|v| v.is_active).count();
    let total = if state.show_stale {
        views.len()
    } else {
        active_count
    };
    state.scroll = state.scroll.min(total.saturating_sub(view_height));
    let scroll = state.scroll;
    let visible_y = |i: usize| -> Option<u16> {
        let row = i.checked_sub(scroll)?;
        (row < view_height).then_some(main.y + row as u16)
    };

    let mut i = 0;
    for v in views.iter().filter(|v| v.is_active) {
        if let Some(y) = visible_y(i) {
            render_active_row(
                frame,
                main,
                y,
                v.base_color,
                v.last_arrived,
                &v.cells,
                &widths,
                v.window_sum,
                max_window_sum,
                window,
            );
        }
        i += 1;
    }
    if state.show_stale {
        for v in views.iter().filter(|v| !v.is_active) {
            if let Some(y) = visible_y(i) {
                render_stale_row(frame, main, y, &v.cells, &widths);
            }
            i += 1;
        }
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

#[allow(clippy::too_many_arguments)]
fn render_active_row(
    frame: &mut Frame,
    area: Rect,
    y: u16,
    base_color: Color,
    last_arrived: Instant,
    cells: &[String; 4],
    widths: &[usize],
    window_sum: usize,
    max_window_sum: usize,
    window: usize,
) {
    let width = (window_sum as f64 / max_window_sum as f64 * area.width as f64) as u16;
    let bg_color = fade(base_color, last_arrived, window);
    let color = text_color(bg_color);
    let bar_width = width.min(area.width);

    let full_rect = Rect {
        x: area.x,
        y,
        width: area.width,
        height: 1,
    };
    let bar = Rect {
        width: bar_width,
        ..full_rect
    };

    frame.render_widget(Block::new().style(Style::default().bg(bg_color)), bar);

    let output = format_cells(cells, widths, 2, area.width as usize);
    frame.render_widget(
        Line::from(output.clone()).style(Style::default().fg(base_color)),
        full_rect,
    );
    frame.render_widget(Line::from(output).style(Style::default().fg(color)), bar);
}

fn render_stale_row(frame: &mut Frame, area: Rect, y: u16, cells: &[String; 4], widths: &[usize]) {
    let style = Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::ITALIC);
    let output = format_cells(cells, widths, 2, area.width as usize);
    let full_rect = Rect {
        x: area.x,
        y,
        width: area.width,
        height: 1,
    };
    frame.render_widget(Line::from(output).style(style), full_rect);
}

fn key_action(
    active: bool,
    prefix: impl Into<Cow<'static, str>>,
    key: impl Into<Cow<'static, str>>,
    suffix: impl Into<Cow<'static, str>>,
) -> [Span<'static>; 3] {
    let amber = if active {
        Style::default().fg(Color::Rgb(255, 191, 0))
    } else {
        Style::default().fg(Color::Rgb(127, 95, 0))
    };
    let text = if active {
        Style::default().fg(Color::Gray)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    [
        Span::styled(prefix, text),
        Span::styled(key, amber),
        Span::styled(suffix, text),
    ]
}

fn legend_line(state: &State) -> Line<'static> {
    let amber = Style::default().fg(Color::Rgb(255, 191, 0));
    let text = Style::default().fg(Color::Gray);
    let mut spans: Vec<Span> = Vec::new();
    spans.extend(key_action(true, "", "r", "eset"));
    spans.push(Span::raw("  "));
    spans.extend(key_action(state.show_stale, "", "s", "tale"));
    spans.push(Span::raw("  "));
    spans.extend(key_action(
        true,
        "",
        "l",
        format!("og [{}]", state.log.len()),
    ));
    spans.push(Span::raw("  "));
    spans.extend(key_action(true, "", "q", "uit"));
    spans.push(Span::raw("  "));
    spans.push(Span::styled("-", amber));
    spans.push(Span::styled("/", text));
    spans.push(Span::styled("+", amber));
    spans.push(Span::styled(format!(": take {}", state.take), text));
    Line::from(spans)
}

fn filters_line(state: &State) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    spans.extend(key_action(state.show_tcp, "", "t", "cp"));
    spans.push(Span::raw("  "));
    spans.extend(key_action(state.show_udp, "", "u", "dp"));
    spans.push(Span::raw("  "));
    spans.extend(key_action(state.show_icmp, "", "i", "cmp"));
    spans.push(Span::raw("  "));
    spans.extend(key_action(state.show_v4, "v", "4", ""));
    spans.push(Span::raw("  "));
    spans.extend(key_action(state.show_v6, "v", "6", ""));
    Line::from(spans)
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
