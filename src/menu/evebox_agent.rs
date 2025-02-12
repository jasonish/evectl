// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::context::Context;
use crate::term;

#[derive(Clone)]
enum Options {
    Toggle,
    Server,
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
            format!("EveBox Server URL [{}]", &config.evebox_agent.server),
        );

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
                Options::Exit => break,
            },
            None => {
                break;
            }
        }
    }

    Ok(())
}

fn set_server(config: &mut Config) -> Result<()> {
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

                if inquire::Confirm::new(&format!("Do you wish to use {} anyway?", &server))
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
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(!with_certificate_validation)
        .build()?;
    let response = client.get(url).send()?;
    if response.status().is_success() {
        Ok(())
    } else {
        bail!("Failed to connect to server: {}", response.status())
    }
}
