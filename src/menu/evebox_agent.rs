// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::context::Context;
use crate::term;

#[derive(Clone)]
enum Options {
    Toggle,
    Server,
    AgentId,
    Key,
    Exit,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    let config = &mut context.config;

    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::new();

        if config.evebox_agent.enabled {
            selections.push(Options::Toggle, "Disable Agent [enabled]");
        } else {
            selections.push(Options::Toggle, "Enable Agent [disabled]");
        }

        selections.push(
            Options::Server,
            format!("EveBox Server URL [{}]", config.evebox_agent.server),
        );

        selections.push(Options::AgentId, agent_id_label(config));
        selections.push(Options::Key, key_label(config));

        selections.push(Options::Exit, "Return");

        match inquire::Select::new("EveCtl: Configure EveBox Agent", selections.to_vec())
            .prompt_skippable()?
        {
            Some(selection) => match selection.tag {
                Options::Toggle => {
                    config.evebox_agent.enabled = !config.evebox_agent.enabled;
                    if config.evebox_agent.enabled && config.evebox_agent.server.is_empty() {
                        set_server(config)?;
                    }
                }
                Options::Server => {
                    set_server(config)?;
                }
                Options::AgentId => {
                    set_agent_id(config);
                }
                Options::Key => {
                    set_key(config);
                }
                Options::Exit => break,
            },
            None => {
                break;
            }
        }
    }

    Ok(())
}

pub(crate) fn agent_id_label(config: &Config) -> String {
    match &config.evebox_agent.agent_id {
        Some(agent_id) => format!("Agent ID [{agent_id}]"),
        None => match evectl::system::hostname() {
            Some(hostname) => format!("Agent ID [not set, defaults to {hostname}]"),
            None => "Agent ID [not set, defaults to the hostname]".to_string(),
        },
    }
}

pub(crate) fn key_label(config: &Config) -> String {
    if config.evebox_agent.key.is_some() {
        "Agent Key [set]".to_string()
    } else {
        "Agent Key [not set]".to_string()
    }
}

/// Prompt for the agent ID. Returns true if an agent ID is set on
/// return, whether or not it was changed.
pub(crate) fn set_agent_id(config: &mut Config) -> bool {
    let current = config
        .evebox_agent
        .agent_id
        .clone()
        .or_else(evectl::system::hostname)
        .unwrap_or_default();
    let prompt = inquire::Text::new("EveBox Agent ID:")
        .with_default(&current)
        .with_help_message("Must match the agent key name on the EveBox server");
    if let Ok(agent_id) = prompt.prompt() {
        let agent_id = agent_id.trim();
        if agent_id.is_empty() {
            config.evebox_agent.agent_id = None;
        } else {
            config.evebox_agent.agent_id = Some(agent_id.to_string());
        }
    }
    config.evebox_agent.agent_id.is_some()
}

/// Prompt for the agent key. Returns true if a key is set on return,
/// whether or not it was changed.
pub(crate) fn set_key(config: &mut Config) -> bool {
    let agent_id = config
        .evebox_agent
        .agent_id
        .clone()
        .or_else(evectl::system::hostname)
        .unwrap_or_else(|| "<agent-id>".to_string());
    let help = format!("Blank to clear. Issue with: evebox config agents add {agent_id}");
    if config.evebox_agent.server.starts_with("http://") {
        warn!("The EveBox server URL is plain HTTP; the agent key will be sent unencrypted");
    }
    let prompt = inquire::Password::new("EveBox Agent Key:")
        .without_confirmation()
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .with_display_toggle_enabled()
        .with_help_message(&help);
    if let Ok(key) = prompt.prompt() {
        let key = key.trim();
        if key.is_empty() {
            if config.evebox_agent.key.is_some()
                && inquire::Confirm::new("Clear Agent Key?")
                    .with_default(true)
                    .prompt()
                    .unwrap_or(false)
            {
                config.evebox_agent.key = None;
            }
        } else {
            config.evebox_agent.key = Some(key.to_string());
        }
    }
    config.evebox_agent.key.is_some()
}

pub(crate) fn set_server(config: &mut Config) -> Result<()> {
    if let Some((server, disable_certificate_validation)) = prompt_for_server_url(config)? {
        config.evebox_agent.server = server;
        config.evebox_agent.disable_certificate_validation = disable_certificate_validation;
    }
    Ok(())
}

pub(crate) fn prompt_for_server_url(config: &Config) -> Result<Option<(String, bool)>> {
    'start: loop {
        let current = config.evebox_agent.server.clone();
        let server = match inquire::Text::new("EveBox Server URL:")
            .with_default(&current)
            .with_help_message("Example: https://example.com:5636")
            .prompt()
        {
            Ok(url) => url,
            Err(_) => return Ok(None),
        };

        if server == current {
            return Ok(None);
        }

        // First, validate the URL.
        let url = match reqwest::Url::parse(&server) {
            Ok(url) => url,
            Err(_) => {
                error!("Invalid URL: {}", &server);
                continue;
            }
        };

        let mut with_certificate_validation = true;

        loop {
            info!("Testing connection to server: {}", &server);
            if let Err(err) = test_url(url.clone(), with_certificate_validation) {
                error!("Failed to connect to server: {}", err);

                if with_certificate_validation && server.starts_with("https") {
                    let msg = "Would you like to try again with certification validation disabled?";
                    if inquire::Confirm::new(msg).with_default(true).prompt()? {
                        with_certificate_validation = false;
                        continue;
                    }
                }

                if inquire::Confirm::new(&format!("Do you wish to use {} anyway?", server))
                    .with_default(false)
                    .prompt()?
                {
                    break;
                } else {
                    continue 'start;
                }
            }
            break;
        }

        return Ok(Some((server, !with_certificate_validation)));
    }
}

fn test_url(url: reqwest::Url, with_certificate_validation: bool) -> Result<()> {
    let client = crate::http::client_builder()
        .danger_accept_invalid_certs(!with_certificate_validation)
        .build()?;
    let response = client.get(url).send()?;
    if response.status().is_success() {
        Ok(())
    } else {
        bail!("Failed to connect to server: {}", response.status())
    }
}
