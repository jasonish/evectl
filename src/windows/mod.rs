// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

// Modules without Win32 or Windows-only crate dependencies are also
// built on other platforms so their tests run everywhere.

#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod cli;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod component;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod evebox;
#[cfg(any(windows, test))]
mod file_extraction;
#[cfg(any(windows, test))]
mod fpc;
#[cfg(windows)]
mod install;
#[cfg(windows)]
mod interfaces;
#[cfg(windows)]
mod menu;
#[cfg(windows)]
mod npcap;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod paths;
#[cfg(windows)]
mod platform;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod rules;
#[cfg(windows)]
mod runtime;
#[cfg(windows)]
mod stack;
#[cfg(windows)]
mod suricata;
#[cfg(windows)]
mod uninstall;
#[cfg(windows)]
mod update;

#[cfg(windows)]
pub(crate) use cli::{Args, Commands, main};

/// Placeholder so the `windows` subcommand parses on other platforms.
#[cfg(not(windows))]
#[derive(clap::Parser, Debug, Clone)]
pub(crate) struct Args;
