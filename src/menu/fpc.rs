// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Full packet capture (FPC) configuration menu.
//!
//! FPC has Suricata write a rotating pcap spool which is served through
//! the EveBox web UI, either by the local EveBox server or by the local
//! EveBox agent on behalf of a remote server. The agent identifies
//! itself with an agent ID and authenticates the packet capture channel
//! with an agent key issued by the server.

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
    Return,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    let config = &mut context.config;

    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::new();

        if config.fpc.enabled {
            selections.push(Options::Toggle, "Disable Full Packet Capture");
        } else {
            selections.push(Options::Toggle, "Enable Full Packet Capture");
        }

        selections.push(
            Options::MaxFiles,
            format!(
                "Retention (current: {} x {} files, ~{} GB)",
                config.fpc.max_files(),
                FpcConfig::FILE_SIZE,
                config.fpc.disk_usage_gb()
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

        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure Full Packet Capture", selections.to_vec())
            .prompt()
        {
            Ok(selection) => match selection.tag {
                Options::Toggle => toggle_enabled(config),
                Options::MaxFiles => set_max_files(config),
                Options::AgentId => {
                    crate::menu::evebox_agent::set_agent_id(config);
                }
                Options::Key => {
                    crate::menu::evebox_agent::set_key(config);
                }
                Options::Return => break,
            },
            Err(_) => break,
        }
    }

    Ok(())
}

fn toggle_enabled(config: &mut Config) {
    if config.fpc.enabled {
        config.fpc.enabled = false;
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
        "Enable full packet capture (up to ~{} GB)?",
        config.fpc.disk_usage_gb()
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
    let prompt = format!(
        "Maximum total number of {} pcap files to retain (across all capture threads):",
        FpcConfig::FILE_SIZE
    );
    if let Ok(value) = inquire::Text::new(&prompt)
        .with_default(&config.fpc.max_files().to_string())
        .prompt()
    {
        match value.trim().parse::<u32>() {
            Ok(n) if n > 0 => {
                config.fpc.max_files = if n == FpcConfig::DEFAULT_MAX_FILES {
                    None
                } else {
                    Some(n)
                };
            }
            _ => error!("Invalid value, must be a positive number"),
        }
    }
}
