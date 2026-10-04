// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;
use crate::prompt::Selections;
use crate::term;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Options {
    Toggle,
    Server,
    AgentId,
    Key,
    Exit,
}

fn menu_options(config: &Config) -> Selections<Options> {
    let mut selections = Selections::new();
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
    selections
}

pub(crate) fn menu(config: &mut Config) -> Result<()> {
    loop {
        term::clear();
        let selections = menu_options(config);
        match selections.prompt("EveCtl: Configure EveBox Agent")? {
            None | Some(Options::Exit) => break,
            Some(action) => crate::prompt::report(
                "EveBox agent configuration failed",
                run_action(config, action),
            ),
        }
    }
    Ok(())
}

fn run_action(config: &mut Config, action: Options) -> Result<()> {
    match action {
        Options::Toggle => {
            config.evebox_agent.enabled = !config.evebox_agent.enabled;
            if config.evebox_agent.enabled && config.evebox_agent.server.is_empty() {
                set_server(config)?;
            }
        }
        Options::Server => set_server(config)?,
        Options::AgentId => {
            set_agent_id(config);
        }
        Options::Key => {
            set_key(config);
        }
        Options::Exit => {}
    }
    Ok(())
}

pub(crate) fn agent_id_label(config: &Config) -> String {
    match &config.evebox_agent.agent_id {
        Some(agent_id) => format!("Agent ID [{agent_id}]"),
        None => match crate::system::hostname() {
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
    let default = config
        .evebox_agent
        .agent_id
        .clone()
        .or_else(crate::system::hostname)
        .unwrap_or_default();
    if let Some(agent_id) = crate::prompt::edit_optional_with(
        config.evebox_agent.agent_id.as_deref(),
        "Clear Agent ID?",
        || {
            inquire::Text::new("EveBox Agent ID:")
                .with_default(&default)
                .with_help_message("Must match the agent key name on the EveBox server")
                .prompt()
                .ok()
        },
    ) {
        config.evebox_agent.agent_id = agent_id;
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
        .or_else(crate::system::hostname)
        .unwrap_or_else(|| "<agent-id>".to_string());
    let help = format!("Blank to clear. Issue with: evebox config agents add {agent_id}");
    if config.evebox_agent.server.starts_with("http://") {
        warn!("The EveBox server URL is plain HTTP; the agent key will be sent unencrypted");
    }
    if let Some(key) = crate::prompt::edit_optional_with(
        config.evebox_agent.key.as_deref(),
        "Clear Agent Key?",
        || {
            inquire::Password::new("EveBox Agent Key:")
                .without_confirmation()
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .with_display_toggle_enabled()
                .with_help_message(&help)
                .prompt()
                .ok()
        },
    ) {
        config.evebox_agent.key = key;
    }
    config.evebox_agent.key.is_some()
}

/// Collect the identity and key used to serve files and packet captures
/// over the agent channel. Returns false if the user backed out.
pub(crate) fn setup_retrieval(config: &mut Config) -> bool {
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
The EveBox agent serves extracted files and packet captures to the server
over an authenticated channel. On the server, create an agent key named
after this agent's ID:

    evebox config agents add {agent_id}

or use the Agents page in the EveBox web UI, then enter the key here.
"
    );

    if config.evebox_agent.agent_id.is_none() && !set_agent_id(config) {
        error!("File and packet retrieval on an agent requires an agent ID");
        crate::prompt::enter();
        return false;
    }

    if config.evebox_agent.key.is_none() && !set_key(config) {
        warn!(
            "No agent key set; the server will reject the retrieval channel unless it allows \
             unauthenticated agents"
        );
        if !crate::prompt::confirm_destructive("Continue without an agent key?") {
            return false;
        }
    }

    true
}

pub(crate) fn set_server(config: &mut Config) -> Result<()> {
    if let Some((server, disable_certificate_validation)) = prompt_for_server_url(config)? {
        config.evebox_agent.server = server;
        config.evebox_agent.disable_certificate_validation = disable_certificate_validation;
    }
    Ok(())
}

/// Prompt for the server URL, testing the connection to a new one.
/// Returns the URL and whether certificate validation is disabled,
/// unchanged if the current URL was kept, or None if the prompt was
/// cancelled.
pub(crate) fn prompt_for_server_url(config: &Config) -> Result<Option<(String, bool)>> {
    let current = config.evebox_agent.server.clone();
    'start: loop {
        let Some(server) = crate::prompt::skippable(
            inquire::Text::new("EveBox Server URL:")
                .with_default(&current)
                .with_help_message("Example: https://example.com:5636")
                .prompt(),
        )?
        else {
            return Ok(None);
        };

        if server == current {
            return Ok(Some((
                server,
                config.evebox_agent.disable_certificate_validation,
            )));
        }

        // First, validate the URL.
        if reqwest::Url::parse(&server).is_err() {
            error!("Invalid URL: {}", &server);
            continue;
        }

        let mut with_certificate_validation = true;

        loop {
            info!("Testing connection to server: {}", &server);
            if let Err(err) = test_url(&server, with_certificate_validation, None) {
                error!("Failed to connect to server: {}", err);

                if with_certificate_validation && server.starts_with("https") {
                    let msg = "Would you like to try again with certification validation disabled?";
                    if crate::prompt::ask(msg, true)? {
                        with_certificate_validation = false;
                        continue;
                    }
                }

                if crate::prompt::ask(&format!("Do you wish to use {} anyway?", server), false)? {
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

/// GET a URL, with optional basic authentication, returning the
/// response body on success.
pub(crate) fn test_url(
    url: &str,
    with_certificate_validation: bool,
    basic_auth: Option<(&str, Option<&str>)>,
) -> Result<String> {
    let client = crate::http::client_builder()
        .danger_accept_invalid_certs(!with_certificate_validation)
        .build()?;
    let mut request = client.get(url);
    if let Some((username, password)) = basic_auth {
        request = request.basic_auth(username, password);
    }
    let response = request.send()?;
    let status = response.status();
    let body = response.text().unwrap_or_default();
    if status.is_success() {
        Ok(body)
    } else {
        bail!("{status}: body={body}")
    }
}
