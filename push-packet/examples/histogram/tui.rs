use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};

pub enum Command {
    Quit,
    Reset,
}

pub fn poll_input() -> color_eyre::Result<Option<Command>> {
    if event::poll(Duration::from_millis(100))? {
        if let Event::Key(k) = event::read()? {
            let ctrl_c =
                k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
            if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) || ctrl_c {
                return Ok(Some(Command::Quit));
            }
            match k.code {
                KeyCode::Char('r') => return Ok(Some(Command::Reset)),
                _ => {}
            }
        }
    }
    Ok(None)
}
