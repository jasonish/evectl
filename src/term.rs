// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crossterm::{
    cursor, execute, style,
    terminal::{Clear, ClearType},
};
use std::io::Write;

/// True if clearing the terminal is disabled by the NO_CLEAR
/// environment variable, mainly for development.
fn no_clear() -> bool {
    std::env::var("NO_CLEAR").is_ok()
}

pub(crate) fn clear() {
    if !no_clear() {
        let mut stdout = std::io::stdout().lock();
        let _ = execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0));
        let _ = stdout.flush();
    }
}

pub(crate) fn title(title: &str) {
    if no_clear() {
        println!("{}\n", title);
    } else {
        let mut stdout = std::io::stdout().lock();
        let _ = execute!(
            stdout,
            Clear(ClearType::All),
            cursor::MoveTo(0, 0),
            style::Print(title),
            cursor::MoveToNextLine(2)
        );
        let _ = stdout.flush();
    }
}
