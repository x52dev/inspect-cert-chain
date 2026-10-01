use std::io;

use ansi_to_tui::IntoText as _;
use crossterm::{
    event::{self, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use der::EncodePem as _;
use ratatui::{
    layout::Constraint,
    prelude::*,
    symbols::border,
    widgets::{
        Block, Borders, List, ListState, Padding, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState,
    },
};
use x509_cert::Certificate;

use crate::{LINE_ENDING, info::write_cert_info};

pub type Tui = Terminal<CrosstermBackend<io::Stdout>>;

/// Sets up terminal for TUI display.
pub(crate) fn init() -> io::Result<Tui> {
    execute!(io::stdout(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    Terminal::new(CrosstermBackend::new(io::stdout()))
}

/// Restores terminal to original state..
pub(crate) fn restore() -> io::Result<()> {
    execute!(io::stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct App {
    certs: Vec<(Certificate, String, usize)>,
    list_state: ListState,
    details_scroll: usize,
    exit: bool,
}

impl App {
    /// Constructs new TUI app widget.
    pub(crate) fn new(certs: &[Certificate]) -> Self {
        Self {
            exit: false,
            list_state: ListState::default().with_selected(Some(0)),
            details_scroll: 0,
            certs: certs
                .iter()
                .cloned()
                .map(|cert| {
                    let mut details = Vec::with_capacity(4_096); // roughly ~4Kb of output

                    write_cert_info(&cert, &mut details, true)
                        .expect("Writing to a Vec always succeeds");

                    let details = String::from_utf8(details)
                        .expect("Everything written to details buffer should be UTF-8");

                    let lines = details.lines().count();

                    (cert, details, lines)
                })
                .collect(),
        }
    }

    /// Runs main execution loop for TUI app.
    pub(crate) fn run(&mut self, tui: &mut Tui) -> io::Result<()> {
        while !self.exit {
            tui.draw(|frame| self.render_frame(frame))?;
            self.handle_events()?;
        }

        Ok(())
    }

    fn render_frame(&mut self, frame: &mut Frame<'_>) {
        // layout

        let (outer_block, list_area, details_area) = self.create_layout(frame);

        // content

        let list = self.create_list();
        let (details, (scrollbar, mut scrollbar_state)) = self.create_details();

        // rendering

        frame.render_widget(outer_block, frame.area());
        frame.render_stateful_widget(list, list_area, &mut self.list_state);
        frame.render_widget(details, details_area);
        frame.render_stateful_widget(scrollbar, details_area, &mut scrollbar_state)
    }

    fn create_layout(&mut self, frame: &mut Frame<'_>) -> (Block<'static>, Rect, Rect) {
        let title = Line::from("inspect-cert-chain".bold());

        let instructions = Line::from(vec![
            " Scroll Up ".into(),
            "<up> ".blue().bold(),
            " Scroll Down ".into(),
            "<down> ".blue().bold(),
            " Copy Public Key ".into(),
            "<Ctrl-P> ".blue().bold(),
            " Quit ".into(),
            "<Q / Ctrl-C> ".blue().bold(),
        ]);

        let outer_block = Block::default()
            .title_top(title.centered())
            .title_bottom(instructions.centered())
            .borders(Borders::ALL)
            .border_set(border::THICK);

        let layout = Layout::vertical([
            Constraint::Length(self.certs.len() as u16 + 1), // list + border
            Constraint::Fill(1),                             // details
        ]);

        let outer_block_area = outer_block.inner(frame.area());
        let [list_area, details_area] = layout.areas(outer_block_area);

        (outer_block, list_area, details_area)
    }

    fn create_list(&self) -> List<'static> {
        let list = self
            .certs
            .iter()
            .map(|(cert, _, _)| cert.tbs_certificate().subject().to_string())
            .collect::<List<'static>>();

        let instructions = Line::from(vec![
            symbols::line::HORIZONTAL.into(),
            " Certificate ".yellow().bold(),
            " Next ".into(),
            "<j> ".blue().bold(),
            " Prev ".into(),
            "<k> ".blue().bold(),
        ]);

        list.highlight_style(Style::new().bold())
            .highlight_symbol("› ")
            .block(
                Block::default()
                    // visual separation from cert details
                    .borders(Borders::BOTTOM)
                    .title_bottom(instructions.centered()),
            )
    }

    fn create_details(&self) -> (Paragraph<'static>, (Scrollbar<'static>, ScrollbarState)) {
        let selected = self.list_state.selected().unwrap();

        let details = self.certs[selected].1.to_owned();

        let scrollbar_state =
            ScrollbarState::new(details.lines().count()).position(self.details_scroll);

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight).track_symbol(None);

        let details = Paragraph::new(details.into_text().expect("Should be valid ANSI"))
            .scroll((self.details_scroll as u16, 0))
            .block(Block::default().padding(Padding::new(1, 2, 1, 1)));

        (details, (scrollbar, scrollbar_state))
    }

    fn handle_events(&mut self) -> io::Result<()> {
        match event::read()? {
            // check that the event is a key press event as crossterm also emits
            // key release and repeat events on Windows
            event::Event::Key(ev) if ev.kind == event::KeyEventKind::Press => {
                self.handle_key_event(ev);
            }

            event::Event::Mouse(ev) => {
                self.handle_mouse_event(ev);
            }

            _ => {}
        };

        Ok(())
    }

    fn handle_key_event(&mut self, ev: event::KeyEvent) {
        let max = self.certs.len() - 1;
        let selected = self.list_state.selected().unwrap();
        let selected_cert_lines = self.certs[selected].2.saturating_sub(1);

        match ev.code {
            event::KeyCode::Char('q') => {
                self.exit = true;
            }

            KeyCode::Char('c') if ev.modifiers.contains(KeyModifiers::CONTROL) => {
                self.exit = true;
            }

            event::KeyCode::Char('k') => {
                self.list_state.select(Some(selected.saturating_sub(1)));

                self.details_scroll = 0;
            }

            event::KeyCode::Char('p') if ev.modifiers.contains(KeyModifiers::CONTROL) => {
                let spki = &self.certs[selected]
                    .0
                    .tbs_certificate()
                    .subject_public_key_info()
                    .to_pem(LINE_ENDING)
                    .expect("SPKI should encode to PEM successfully");

                let mut clipboard = arboard::Clipboard::new().expect("Clipboard should initialize");
                clipboard
                    .set_text(spki)
                    .expect("Clipboard should be usable");
            }

            event::KeyCode::Char('j') => {
                self.list_state
                    .select(Some(selected.saturating_add(1).clamp(0, max)));

                self.details_scroll = 0;
            }

            event::KeyCode::Up => {
                self.details_scroll = self.details_scroll.saturating_sub(1);
            }

            event::KeyCode::PageUp => {
                self.details_scroll = self.details_scroll.saturating_sub(10);
            }

            event::KeyCode::Down => {
                self.details_scroll = self
                    .details_scroll
                    .saturating_add(1)
                    .clamp(0, selected_cert_lines);
            }

            event::KeyCode::PageDown => {
                self.details_scroll = self
                    .details_scroll
                    .saturating_add(10)
                    .clamp(0, selected_cert_lines);
            }

            _ => {}
        }
    }

    fn handle_mouse_event(&mut self, ev: event::MouseEvent) {
        match ev.kind {
            event::MouseEventKind::ScrollUp => {
                self.details_scroll = self.details_scroll.saturating_sub(1);
            }

            event::MouseEventKind::ScrollDown => {
                self.details_scroll = self.details_scroll.saturating_add(1);
            }

            _ => {}
        }
    }
}
