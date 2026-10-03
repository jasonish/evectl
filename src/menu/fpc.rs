// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Full packet capture (FPC) configuration menu.
//!
//! FPC has Suricata write a rotating pcap spool which is served through
//! the EveBox web UI, either by the local EveBox server or by the local
//! EveBox agent on behalf of a remote server. The agent identifies
//! itself with an agent ID and authenticates the packet capture channel
//! with an agent key issued by the server.

use std::path::Path;

use crate::config::FpcConfig;
use crate::context::Context;
use crate::fpc::{Backend, ContainerBackend};
use crate::prelude::*;
use crate::prompt::Selections;
use crate::term;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Options {
    Toggle,
    MaxFiles,
    AgentId,
    Key,
    RemoveSpool,
    Return,
}

/// Only runtime paths and cleanup image choices use the snapshot; settings
/// are edited directly in the caller's configuration.
pub(crate) fn container_menu(context: &mut Context) -> Result<()> {
    let runtime = context.clone();
    menu(&mut context.config, &ContainerBackend(&runtime))
}

fn menu_options(config: &Config, spool: &Path) -> Selections<Options> {
    let mut selections = Selections::new();
    selections.push(
        Options::Toggle,
        if config.fpc.enabled {
            "Disable Full Packet Capture"
        } else {
            "Enable Full Packet Capture"
        },
    );
    let threads = FpcConfig::capture_threads();
    selections.push(
        Options::MaxFiles,
        format!(
            "Retention (current: {} x {} files, ~{}; {} per capture thread x {} threads)",
            config.fpc.effective_max_files(),
            FpcConfig::FILE_SIZE,
            config.fpc.disk_usage(),
            config.fpc.max_files_per_thread(threads),
            threads,
        ),
    );

    if config.evebox_agent.enabled {
        selections.push(
            Options::AgentId,
            crate::menu::evebox_agent::agent_id_label(config),
        );
        selections.push(Options::Key, crate::menu::evebox_agent::key_label(config));
    }
    // Captures left behind after disabling are no longer managed.
    if !config.fpc.enabled {
        let size = spool_size(spool);
        if size > 0 {
            selections.push(
                Options::RemoveSpool,
                format!(
                    "Remove existing packet captures (~{} in {})",
                    format_size(size),
                    spool.display(),
                ),
            );
        }
    }
    selections.push(Options::Return, "Return");
    selections
}

pub(crate) fn menu(config: &mut Config, backend: &dyn Backend) -> Result<()> {
    let spool = backend.spool_dir()?;
    loop {
        term::clear();
        println!("Packet captures: {}", spool.display());
        println!("Captures are available through the EveBox server or agent.");
        println!("Changes take effect after restarting services.");
        let selections = menu_options(config, &spool);
        let selection = match inquire::Select::new(
            "EveCtl: Configure Full Packet Capture",
            selections.to_vec(),
        )
        .with_page_size(selections.page_size())
        .prompt()
        {
            Ok(selection) => selection,
            Err(
                inquire::InquireError::OperationCanceled
                | inquire::InquireError::OperationInterrupted,
            ) => break,
            Err(err) => return Err(err.into()),
        };
        if selection.tag == Options::Return {
            break;
        }
        if let Err(err) = run_action(config, backend, &spool, selection.tag) {
            error!("Packet-capture configuration failed: {err:#}");
            crate::prompt::enter();
        }
    }
    Ok(())
}

fn run_action(
    config: &mut Config,
    backend: &dyn Backend,
    spool: &Path,
    action: Options,
) -> Result<()> {
    match action {
        Options::Toggle => toggle_enabled(config, spool)?,
        Options::MaxFiles => set_max_files(config),
        Options::AgentId => {
            crate::menu::evebox_agent::set_agent_id(config);
        }
        Options::Key => {
            crate::menu::evebox_agent::set_key(config);
        }
        Options::RemoveSpool => {
            if config.fpc.enabled {
                bail!("Disable full packet capture before removing packet captures");
            }
            remove_spool(backend, crate::prompt::confirm_destructive)?;
        }
        Options::Return => {}
    }
    Ok(())
}

/// Total size of the files in the spool directory, best effort.
fn spool_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|entry| entry.metadata().ok())
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
        .sum()
}

pub(crate) fn format_size(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{} MB", bytes.div_ceil(MB))
    }
}

fn toggle_enabled(config: &mut Config, spool: &Path) -> Result<()> {
    if config.fpc.enabled {
        config.fpc.enabled = false;
        if spool_size(spool) > 0 {
            info!(
                "Existing packet captures remain in {}; they can be removed from this menu after \
                 restarting services",
                spool.display()
            );
            crate::prompt::enter();
        }
        return Ok(());
    }

    enable_capture(
        config,
        crate::menu::evebox_agent::setup_retrieval,
        crate::prompt::confirm_destructive,
    )
}

fn enable_capture(
    config: &mut Config,
    setup_retrieval: impl FnOnce(&mut Config) -> bool,
    confirm: impl FnOnce(&str) -> bool,
) -> Result<()> {
    if !config.suricata.enabled || !(config.evebox_server.enabled || config.evebox_agent.enabled) {
        bail!(
            "Full packet capture requires Suricata and either the EveBox server or the EveBox \
             agent to be enabled (Suricata enabled: {}, EveBox server enabled: {}, EveBox agent \
             enabled: {})",
            config.suricata.enabled,
            config.evebox_server.enabled,
            config.evebox_agent.enabled
        );
    }

    // An enabled agent always serves the spool, even alongside a local server.
    if config.evebox_agent.enabled && !setup_retrieval(config) {
        return Ok(());
    }
    let message = format!(
        "Enable full packet capture (up to ~{})?",
        config.fpc.disk_usage()
    );
    if confirm(&message) {
        config.fpc.enabled = true;
    }
    Ok(())
}

fn parse_max_files(input: &str, threads: usize) -> std::result::Result<u32, String> {
    match input.trim().parse::<u32>() {
        Ok(n) if n as usize >= threads => Ok(n),
        Ok(_) => Err(format!(
            "Must be at least {threads}, one file per capture thread"
        )),
        Err(_) => Err("Must be a positive number".into()),
    }
}

fn set_max_files(config: &mut Config) {
    let threads = FpcConfig::capture_threads();
    let prompt = format!(
        "Maximum total number of {} pcap files to retain (across all capture threads):",
        FpcConfig::FILE_SIZE
    );
    let help =
        format!("Rounded down to a multiple of {threads} capture threads (minimum {threads})");
    let validator = move |input: &str| {
        Ok(match parse_max_files(input, threads) {
            Ok(_) => inquire::validator::Validation::Valid,
            Err(message) => inquire::validator::Validation::Invalid(message.into()),
        })
    };
    if let Ok(value) = inquire::Text::new(&prompt)
        .with_default(&config.fpc.max_files().to_string())
        .with_help_message(&help)
        .with_validator(validator)
        .prompt()
        && let Ok(n) = parse_max_files(&value, threads)
    {
        config.fpc.max_files = if n == FpcConfig::DEFAULT_MAX_FILES {
            None
        } else {
            Some(n)
        };
    }
}

fn remove_spool(backend: &dyn Backend, confirm: impl FnOnce(&str) -> bool) -> Result<()> {
    backend.check_remove_spool()?;
    let spool = backend.spool_dir()?;
    let question = format!(
        "Remove all packet captures in {} (~{})?",
        spool.display(),
        format_size(spool_size(&spool)),
    );
    if confirm(&question) {
        backend.remove_spool()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
