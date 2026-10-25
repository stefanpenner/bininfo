/*
---
why: This file draws the folded page in the terminal.
uses: bininfo
how: The bininfo command calls this file when stdout is a terminal.
This file reads keys and draws the page.
---
*/

//! Draw the folded page. Keys move, open, close, and search.

use super::fold::{self, View};
use bininfo::links;
use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, Print, SetAttribute};
use crossterm::terminal::{
    self, Clear, ClearType, DisableLineWrap, EnableLineWrap, EnterAlternateScreen,
    LeaveAlternateScreen,
};
use crossterm::{execute, queue};
use std::io::{self, Write};
use std::sync::mpsc;
use std::time::Duration;

const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Draw the page. `load` returns the full page and runs on a thread when the user opens `certs`.
pub(crate) fn run(page: &str, load: impl FnOnce() -> String + Send + 'static) -> io::Result<()> {
    let mut load = Some(load);
    let mut pending: Option<mpsc::Receiver<String>> = None;
    let mut tick = 0usize;
    let mut g_pending = false;
    let mut note: Option<String> = None;
    let mut view = View::spine(page);
    let mut stdout = io::stdout();
    terminal::enable_raw_mode()?;
    let _guard = Restorer;
    execute!(stdout, EnterAlternateScreen, Hide, DisableLineWrap)?;
    let mut typed = String::new();
    let mut search = false;
    loop {
        let busy = pending.is_some().then(|| SPINNER[tick % SPINNER.len()]);
        draw(&mut stdout, &view, search.then_some(typed.as_str()), busy, note.as_deref())?;
        if let Some(rx) = &pending {
            match rx.try_recv() {
                Ok(full) => {
                    view = View::spine(&full);
                    view.focus("certs");
                    pending = None;
                    continue;
                }
                Err(mpsc::TryRecvError::Disconnected) => pending = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            tick += 1;
            if !event::poll(Duration::from_millis(80))? {
                continue;
            }
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            note = None;
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                break;
            }
            if search {
                match key.code {
                    KeyCode::Enter => {
                        view.accept_search();
                        search = false;
                    }
                    KeyCode::Esc => {
                        view.cancel_search();
                        search = false;
                    }
                    KeyCode::Backspace => {
                        typed.pop();
                        view.live(&typed);
                    }
                    KeyCode::Char(ch) => {
                        typed.push(ch);
                        view.live(&typed);
                    }
                    _ => {}
                }
                continue;
            }
            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            let page = terminal::size().map_or(10, |(_, rows)| rows as isize / 2);
            if key.code == KeyCode::Char('g') {
                if g_pending {
                    view.top();
                }
                g_pending = !g_pending;
                continue;
            }
            g_pending = false;
            match key.code {
                KeyCode::Char('o') => {
                    note = Some(match links::for_block(&view.cursor_block()) {
                        Some(link) => match links::open(&link.url) {
                            Ok(()) => format!("opened {}: {}", link.label, link.url),
                            Err(err) => format!("cannot open {}: {err}", link.url),
                        },
                        None => "nothing to open here".to_string(),
                    });
                }
                KeyCode::Char('G') | KeyCode::End => view.bottom(),
                KeyCode::Home | KeyCode::Char('<') => view.top(),
                KeyCode::Char('>') => view.bottom(),
                KeyCode::Char('d') if ctrl => view.jump(page),
                KeyCode::Char('u') if ctrl => view.jump(-page),
                KeyCode::PageDown | KeyCode::Char(' ') => view.jump(page * 2),
                KeyCode::PageUp => view.jump(-page * 2),
                KeyCode::Char('n') if ctrl => view.down(),
                KeyCode::Char('p') if ctrl => view.up(),
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('j') | KeyCode::Down => view.down(),
                KeyCode::Char('k') | KeyCode::Up => view.up(),
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                    if view.cursor_key() == "certs" {
                        if let Some(job) = load.take() {
                            let (tx, rx) = mpsc::channel();
                            std::thread::spawn(move || {
                                let _ = tx.send(job());
                            });
                            pending = Some(rx);
                        }
                    }
                    view.open();
                }
                KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => view.close(),
                KeyCode::Char('/') => {
                    typed.clear();
                    view.begin_search();
                    search = true;
                }
                KeyCode::Char('n') => view.next(),
                _ => {}
            }
        }
    }
    Ok(())
}

fn draw(
    out: &mut io::Stdout,
    view: &View,
    query: Option<&str>,
    busy: Option<char>,
    note: Option<&str>,
) -> io::Result<()> {
    let (cols, rows) = terminal::size()?;
    let width = cols as usize;
    let lines = view.slots_text();
    let cursor = view.cursor_slot();
    let body = rows.saturating_sub(1) as usize;
    let start = window_start(cursor, lines.len(), body);
    queue!(out, MoveTo(0, 0), Clear(ClearType::All))?;
    for (row, line) in lines.iter().skip(start).take(body).enumerate() {
        queue!(out, MoveTo(0, row as u16))?;
        if start + row == cursor {
            let plain = fold::strip_ansi(line);
            queue!(
                out,
                SetAttribute(Attribute::Reverse),
                Print(fit(&plain, width)),
                SetAttribute(Attribute::Reset)
            )?;
        } else {
            queue!(out, Print(fit(line, width)), Print("\x1b[0m"))?;
        }
    }
    let status = match query {
        None if busy.is_some() => format!(
            "{} scanning certs and fetching bad lists...    q quit",
            busy.unwrap_or(' ')
        ),
        Some(text) if view.searching_none() => format!("/{text}    no match"),
        Some(text) => format!("/{text}"),
        None if note.is_some() => note.unwrap_or("").to_string(),
        None => {
            let open = links::for_block(&view.cursor_block())
                .map_or(String::new(), |link| format!("    o open {}", link.label));
            format!(
                "j/k move    gg/G top/bottom    enter fold    / search    n next{open}    q quit"
            )
        }
    };
    queue!(
        out,
        MoveTo(0, rows.saturating_sub(1)),
        SetAttribute(Attribute::Reverse),
        Print(fit(&status, width)),
        SetAttribute(Attribute::Reset)
    )?;
    out.flush()
}

fn window_start(cursor: usize, len: usize, height: usize) -> usize {
    if height == 0 || len <= height {
        return 0;
    }
    let half = height / 2;
    cursor.saturating_sub(half).min(len - height)
}

fn fit(line: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut seen = 0usize;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            out.push(ch);
            if let Some(next) = chars.next() {
                out.push(next);
            }
            for next in chars.by_ref() {
                out.push(next);
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if seen >= width {
            break;
        }
        out.push(ch);
        seen += 1;
    }
    out
}

struct Restorer;

impl Drop for Restorer {
    fn drop(&mut self) {
        let mut stdout = io::stdout();
        let _ = execute!(
            stdout,
            EnableLineWrap,
            Show,
            LeaveAlternateScreen,
            SetAttribute(Attribute::Reset)
        );
        let _ = terminal::disable_raw_mode();
    }
}
