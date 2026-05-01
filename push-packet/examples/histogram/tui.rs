use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};

pub enum Command {
    Quit,
    Reset,
    ScrollUp,
    ScrollDown,
    ToggleStale,
    ToggleLog,
}

pub fn poll_input() -> color_eyre::Result<Vec<Command>> {
    let mut cmds = vec![];
    if !event::poll(Duration::from_millis(100))? {
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
