// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Relaying the output of foreground child processes to the terminal.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::Child;
use std::sync::mpsc::Sender;
use std::thread;

use colored::Colorize;

use crate::prelude::*;

/// Add some coloring to a Suricata log line, as Suricata doesn't add
/// its own color when writing to a non-interactive terminal.
pub(crate) fn colorize_suricata_line(line: &str) -> String {
    if line.starts_with("Info") {
        line.green().to_string()
    } else if line.starts_with("Error") {
        line.red().to_string()
    } else if line.starts_with("Notice") {
        line.magenta().to_string()
    } else if line.starts_with("Warn") {
        line.yellow().to_string()
    } else {
        line.to_string()
    }
}

/// Print each line of `output` to stdout prefixed with `label`,
/// signaling `done` when the output ends.
fn pipe_lines<R: Read + Send + 'static>(
    output: R,
    label: &'static str,
    colorize: bool,
    done: Option<Sender<bool>>,
) {
    for line in BufReader::new(output).lines() {
        let Ok(line) = line else {
            debug!("{}: EOF", label);
            break;
        };
        let line = if colorize {
            colorize_suricata_line(&line)
        } else {
            line
        };
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(&mut stdout, "{}: {}", label, line);
        let _ = stdout.flush();
    }
    if let Some(done) = done {
        let _ = done.send(true);
    }
}

/// Relay the child's stdout and stderr to the terminal on background
/// threads, each line prefixed with `label`. Each stream signals
/// `done` when it ends.
pub(crate) fn pipe_output(
    child: &mut Child,
    label: &'static str,
    colorize: bool,
    done: Option<Sender<bool>>,
) {
    if let Some(stdout) = child.stdout.take() {
        let done = done.clone();
        thread::spawn(move || pipe_lines(stdout, label, colorize, done));
    }
    if let Some(stderr) = child.stderr.take() {
        thread::spawn(move || pipe_lines(stderr, label, colorize, done));
    }
}
