// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Full packet capture (FPC) configuration menu.
//!
//! FPC has Suricata write a rotating pcap spool which is served through
//! the EveBox web UI, either by the local EveBox server or by the local
//! EveBox agent on behalf of a remote server. The agent identifies
//! itself with an agent ID and authenticates the packet capture channel
//! with an agent key issued by the server.

use std::path::{Path, PathBuf};

use crate::config::FpcConfig;
use crate::context::Context;
use crate::prelude::*;
use crate::term;

#[derive(Clone)]
enum Options {
    Toggle,
    MaxFiles,
    AgentId,
    Key,
    RemoveSpool,
    Return,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    loop {
        term::clear();

        let config = &context.config;
        let mut selections = crate::prompt::Selections::new();

        if config.fpc.enabled {
            selections.push(Options::Toggle, "Disable Full Packet Capture");
        } else {
            selections.push(Options::Toggle, "Enable Full Packet Capture");
        }

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

        // Served by the agent: the server needs to know who this is.
        if config.evebox_agent.enabled {
            selections.push(
                Options::AgentId,
                crate::menu::evebox_agent::agent_id_label(config),
            );
            selections.push(Options::Key, crate::menu::evebox_agent::key_label(config));
        }

        // Captures left behind after disabling are not managed by
        // anything, so offer to clean them up here.
        let spool = spool_dir(context);
        let spool_size = if config.fpc.enabled {
            0
        } else {
            spool_size(&spool)
        };
        if spool_size > 0 {
            selections.push(
                Options::RemoveSpool,
                format!(
                    "Remove existing packet captures (~{} in {})",
                    format_size(spool_size),
                    spool.display()
                ),
            );
        }

        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure Full Packet Capture", selections.to_vec())
            .prompt()
        {
            Ok(selection) => match selection.tag {
                Options::Toggle => toggle_enabled(context),
                Options::MaxFiles => set_max_files(&mut context.config),
                Options::AgentId => {
                    crate::menu::evebox_agent::set_agent_id(&mut context.config);
                }
                Options::Key => {
                    crate::menu::evebox_agent::set_key(&mut context.config);
                }
                Options::RemoveSpool => remove_spool(context, &spool),
                Options::Return => break,
            },
            Err(_) => break,
        }
    }

    Ok(())
}

/// Host path of the pcap spool, bind mounted into the containers as
/// /var/log/suricata/pcap.
fn spool_dir(context: &Context) -> PathBuf {
    context.data_dir().join("suricata").join("log").join("pcap")
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

fn format_size(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{} MB", bytes.div_ceil(MB))
    }
}

fn toggle_enabled(context: &mut Context) {
    let config = &mut context.config;

    if config.fpc.enabled {
        config.fpc.enabled = false;
        let spool = spool_dir(context);
        if spool_size(&spool) > 0 {
            info!(
                "Existing packet captures remain in {}; they can be removed from this menu after \
                 restarting services",
                spool.display()
            );
            crate::prompt::enter();
        }
        return;
    }

    if !config.suricata.enabled || !(config.evebox_server.enabled || config.evebox_agent.enabled) {
        error!(
            "Full packet capture requires Suricata and either the EveBox server or the EveBox \
             agent to be enabled (Suricata enabled: {}, EveBox server enabled: {}, EveBox agent \
             enabled: {})",
            config.suricata.enabled, config.evebox_server.enabled, config.evebox_agent.enabled
        );
        crate::prompt::enter();
        return;
    }

    // The agent is given the spool whenever it is enabled, even
    // alongside a local server (see `uses_fpc`), so it always needs
    // its identity and key.
    if config.evebox_agent.enabled && !setup_agent(config) {
        return;
    }

    let message = format!(
        "Enable full packet capture (up to ~{})?",
        config.fpc.disk_usage()
    );
    if inquire::Confirm::new(&message)
        .with_default(false)
        .prompt()
        .unwrap_or(false)
    {
        config.fpc.enabled = true;
    }
}

/// Collect what the agent needs to serve captures to the server: an
/// agent ID the server can route capture requests to, and the agent
/// key issued for that ID. Returns false if the user backed out.
fn setup_agent(config: &mut Config) -> bool {
    if config.evebox_agent.agent_id.is_some() && config.evebox_agent.key.is_some() {
        return true;
    }

    let agent_id = config
        .evebox_agent
        .agent_id
        .clone()
        .unwrap_or_else(|| "<agent-id>".to_string());
    println!(
        "
The EveBox agent serves packet captures to the server over an
authenticated channel. On the server, create an agent key named after
this agent's ID:

    evebox config agents add {agent_id}

or use the Agents page in the EveBox web UI, then enter the key here.
"
    );

    if config.evebox_agent.agent_id.is_none() && !crate::menu::evebox_agent::set_agent_id(config) {
        error!("Full packet capture on an agent requires an agent ID");
        crate::prompt::enter();
        return false;
    }

    if config.evebox_agent.key.is_none() && !crate::menu::evebox_agent::set_key(config) {
        warn!(
            "No agent key set; the server will reject the capture channel unless it allows \
             unauthenticated agents"
        );
        if !inquire::Confirm::new("Continue without an agent key?")
            .with_default(false)
            .prompt()
            .unwrap_or(false)
        {
            return false;
        }
    }

    true
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
        Ok(match input.trim().parse::<u32>() {
            Ok(n) if n as usize >= threads => inquire::validator::Validation::Valid,
            Ok(_) => inquire::validator::Validation::Invalid(
                format!("Must be at least {threads}, one file per capture thread").into(),
            ),
            Err(_) => inquire::validator::Validation::Invalid("Must be a positive number".into()),
        })
    };
    if let Ok(value) = inquire::Text::new(&prompt)
        .with_default(&config.fpc.max_files().to_string())
        .with_help_message(&help)
        .with_validator(validator)
        .prompt()
        && let Ok(n) = value.trim().parse::<u32>()
    {
        config.fpc.max_files = if n == FpcConfig::DEFAULT_MAX_FILES {
            None
        } else {
            Some(n)
        };
    }
}

fn remove_spool(context: &Context, spool: &Path) {
    let suricata = crate::suricata::container_name(context);
    if context.manager.is_running(&suricata) {
        error!("Suricata is running; stop or restart services before removing packet captures");
        crate::prompt::enter();
        return;
    }

    let prompt = format!(
        "Remove all packet captures in {} (~{})?",
        spool.display(),
        format_size(spool_size(spool))
    );
    if !crate::prompt::confirm_destructive(&prompt) {
        return;
    }

    if let Err(err) = crate::uninstall::remove_directory(context, spool) {
        error!("{err:#}");
        crate::prompt::enter();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_size_sums_files_only() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(spool_size(dir.path()), 0);
        std::fs::write(dir.path().join("log.0.1.pcap"), [0u8; 1000]).unwrap();
        std::fs::write(dir.path().join("log.1.1.pcap"), [0u8; 24]).unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        assert_eq!(spool_size(dir.path()), 1024);
        assert_eq!(spool_size(&dir.path().join("missing")), 0);
    }

    #[test]
    fn format_size_rounds_sensibly() {
        assert_eq!(format_size(1), "1 MB");
        assert_eq!(format_size(256 * 1024 * 1024), "256 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(
            format_size(25 * 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "25.5 GB"
        );
    }
}
