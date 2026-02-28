// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::{config::EveBoxServerConfig, context::Context, term};

#[derive(Clone)]
enum Options {
    EnableToggle,
    ToggleTls,
    ToggleAuth,
    ResetPassword,
    EnableRemote,
    DisableRemote,
    SetBindAddress,
    ToggleElasticsearch,
    UseExternalElasticsearch,
    ElasticsearchUrl,
    Return,
}

#[derive(Clone)]
struct BindAddressOption {
    label: String,
    address: Option<String>,
}

impl std::fmt::Display for BindAddressOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    //let config = &context.config.evebox_server;
    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::with_index();

        if context.config.evebox_server.enabled {
            let database = if context.config.evebox_server.use_external_elasticsearch {
                "external elasticsearch"
            } else if context.config.elasticsearch.enabled {
                "managed elasticsearch"
            } else {
                "embedded sqlite"
            };
            selections.push(
                Options::EnableToggle,
                format!("Disable EveBox Server [enabled, {}]", database),
            );
        } else {
            selections.push(Options::EnableToggle, "Enable EveBox Server [disabled]");
        }

        if context.config.evebox_server.allow_remote {
            selections.push(Options::DisableRemote, "Disable Remote Access [enabled]");

            let bind_label = if let Some(value) = &context.config.evebox_server.bind_address {
                if value.parse::<std::net::IpAddr>().is_ok() {
                    format!("Bind Address [{}]", value)
                } else {
                    format!("Bind Address [interface: {}]", value)
                }
            } else {
                "Bind Address [all interfaces]".to_string()
            };
            selections.push(Options::SetBindAddress, bind_label);
        } else {
            selections.push(Options::EnableRemote, "Enable Remote Access [disabled]");
        }
        selections.push(
            Options::ToggleTls,
            format!(
                "Toggle TLS [{}]",
                if context.config.evebox_server.no_tls {
                    "disabled"
                } else {
                    "enabled"
                }
            ),
        );
        selections.push(
            Options::ToggleAuth,
            format!(
                "Toggle authentication [{}]",
                if context.config.evebox_server.no_auth {
                    "disabled"
                } else {
                    "enabled"
                }
            ),
        );

        selections.push(
            Options::ToggleElasticsearch,
            format!(
                "Use Managed Elasticsearch [{}]",
                if context.config.elasticsearch.enabled {
                    "true"
                } else {
                    "false"
                }
            ),
        );

        selections.push(
            Options::UseExternalElasticsearch,
            format!("Use External Elasticsearch [{}]", {
                if context.config.evebox_server.use_external_elasticsearch {
                    "true"
                } else {
                    "false"
                }
            }),
        );

        if context.config.evebox_server.use_external_elasticsearch {
            selections.push(
                Options::ElasticsearchUrl,
                format!(
                    "External Elasticsearch URL: [{}]",
                    context
                        .config
                        .evebox_server
                        .elasticsearch_client
                        .url
                        .as_deref()
                        .unwrap_or("not set")
                ),
            );
        }

        selections.push(Options::ResetPassword, "Reset Admin Password");
        selections.push(Options::Return, "Return");

        if let Ok(selection) =
            inquire::Select::new("EveCtl: Configure EveBox Server", selections.to_vec())
                .with_page_size(16)
                .prompt()
        {
            match selection.tag {
                Options::EnableToggle => {
                    context.config.evebox_server.enabled = !context.config.evebox_server.enabled;
                }
                Options::ToggleTls => toggle_tls(&mut context.config.evebox_server),
                Options::ToggleAuth => toggle_auth(&mut context.config.evebox_server),
                Options::ResetPassword => crate::evebox::server::reset_password(context),
                Options::EnableRemote => enable_remote_access(context),
                Options::DisableRemote => disable_remote_access(context),
                Options::SetBindAddress => set_bind_address(context),
                Options::ToggleElasticsearch => toggle_elasticsearch(context)?,
                Options::UseExternalElasticsearch => use_external_elasticsearch(context)?,
                Options::ElasticsearchUrl => {
                    set_elasticsearch_url(context)?;
                }
                Options::Return => break,
            }
        } else {
            break;
        }
    }

    Ok(())
}

fn toggle_elasticsearch(context: &mut Context) -> Result<()> {
    if context.config.evebox_server.use_external_elasticsearch {
        warn!("Using managed Elasticsearch will disable use of the external Elasticsearch server.");
        if !inquire::Confirm::new("Continue?")
            .with_default(true)
            .prompt()?
        {
            return Ok(());
        }
    }
    context.config.elasticsearch.enabled = !context.config.elasticsearch.enabled;
    if context.config.elasticsearch.enabled {
        context.config.evebox_server.use_external_elasticsearch = false;
    }
    Ok(())
}

fn use_external_elasticsearch(context: &mut Context) -> Result<()> {
    if context.config.evebox_server.use_external_elasticsearch {
        context.config.evebox_server.use_external_elasticsearch = false;
    } else {
        if context.config.elasticsearch.enabled {
            warn!(
                "Using external Elasticsearch will disable use of the managed Elasticsearch server."
            );
            if !inquire::Confirm::new("Continue?")
                .with_default(true)
                .prompt()?
            {
                return Ok(());
            }
        }
        context.config.evebox_server.use_external_elasticsearch = true;
        set_elasticsearch_url(context)?;
    }
    Ok(())
}

fn toggle_tls(config: &mut EveBoxServerConfig) {
    if config.no_tls {
        config.no_tls = false;
    } else {
        if config.allow_remote {
            match inquire::Confirm::new(
                "Remote access is enabled, are you sure you want to disable TLS",
            )
            .with_default(false)
            .prompt()
            {
                Ok(true) => {}
                Ok(false) | Err(_) => return,
            }
        }
        config.no_tls = true;
    }
}

fn toggle_auth(config: &mut EveBoxServerConfig) {
    if config.no_auth {
        config.no_tls = false;
    } else {
        if config.allow_remote {
            match inquire::Confirm::new(
                "Remote access is enabled, are you sure you want to disable authentication",
            )
            .with_default(false)
            .prompt()
            {
                Ok(true) => {}
                Ok(false) | Err(_) => return,
            }
        }
        config.no_auth = true;
    }
}

fn enable_remote_access(context: &mut Context) {
    if context.config.evebox_server.no_tls {
        warn!("Enabling TLS");
        context.config.evebox_server.no_tls = false;
    }
    if context.config.evebox_server.no_auth {
        warn!("Enabling authentication");
        context.config.evebox_server.no_auth = false;
    }
    context.config.evebox_server.allow_remote = true;

    if let Ok(true) = inquire::Confirm::new("Do you wish to reset the admin password")
        .with_default(true)
        .prompt()
    {
        crate::evebox::server::reset_password(context);
    }
}

fn disable_remote_access(context: &mut Context) {
    context.config.evebox_server.allow_remote = false;
}

fn set_bind_address(context: &mut Context) {
    let interfaces = match evectl::system::get_interfaces() {
        Ok(interfaces) => interfaces,
        Err(err) => {
            error!("Failed to get network interfaces: {}", err);
            return;
        }
    };

    let mut available: Vec<(String, String)> = vec![];
    for iface in interfaces {
        for addr in iface.addr4 {
            available.push((iface.name.clone(), addr));
        }
    }

    if available.is_empty() {
        error!("No network interfaces with IPv4 addresses found");
        return;
    }

    let mut options = vec![BindAddressOption {
        label: "All interfaces".to_string(),
        address: None,
    }];

    for (iface, addr) in &available {
        options.push(BindAddressOption {
            label: format!("{} ({})", addr, iface),
            address: Some(addr.to_string()),
        });
    }

    let default_index = if let Some(current) = &context.config.evebox_server.bind_address {
        if current.parse::<std::net::IpAddr>().is_ok() {
            options
                .iter()
                .position(|option| option.address.as_ref() == Some(current))
                .unwrap_or(0)
        } else {
            available
                .iter()
                .position(|(iface, _)| iface == current)
                .map(|i| i + 1) // +1 because "All interfaces" is at index 0
                .unwrap_or(0)
        }
    } else {
        0
    };

    if let Ok(selection) = inquire::Select::new("Select address to bind to:", options)
        .with_starting_cursor(default_index)
        .prompt()
    {
        context.config.evebox_server.bind_address = selection.address;
    }
}

fn set_elasticsearch_url(context: &mut Context) -> Result<()> {
    let mut url = context
        .config
        .evebox_server
        .elasticsearch_client
        .url
        .clone()
        .unwrap_or_default();
    let mut index = context
        .config
        .evebox_server
        .elasticsearch_client
        .index
        .clone()
        .unwrap_or_else(|| "evebox".to_string());
    let mut username = context
        .config
        .evebox_server
        .elasticsearch_client
        .username
        .clone()
        .unwrap_or_default();
    let mut password = context
        .config
        .evebox_server
        .elasticsearch_client
        .password
        .clone()
        .unwrap_or_default();

    loop {
        url = inquire::Text::new("Enter the Elasticsearch URL:")
            .with_placeholder("http://elasticsearch:9200")
            .with_default(&url)
            .prompt()?;
        if url.is_empty() {
            return Ok(());
        }
        index = inquire::Text::new("Enter the Elasticsearch index:")
            .with_default(&index)
            .prompt()?;
        username = inquire::Text::new("Enter the Elasticsearch username:")
            .with_default(&username)
            .with_help_message("Username is optional; ESC to clear current username.")
            .prompt_skippable()?
            .unwrap_or_default();
        password = inquire::Text::new("Enter the Elasticsearch password:")
            .with_default(&password)
            .with_help_message(
                "Password is option; ESC to clear current password. Note: password not masked.",
            )
            .prompt_skippable()?
            .unwrap_or_default();
        let disable_certificate_validation = if url.starts_with("https://") {
            inquire::Confirm::new("Disable certificate validation?")
                .with_default(false)
                .prompt()?
        } else {
            false
        };

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(disable_certificate_validation)
            .build()?;
        let mut request = client.get(&url);
        if !username.is_empty() {
            let password = if password.is_empty() {
                None
            } else {
                Some(password.clone())
            };
            request = request.basic_auth(&username, password);
        }
        let success = match request.send() {
            Ok(response) => {
                let status = response.status();
                let success = status.is_success();
                let body = response.text().ok();
                if success {
                    info!(
                        "Connected successfully to Elasticsearch: body={}",
                        body.unwrap_or_default()
                    );
                    true
                } else {
                    error!(
                        "Failed to connect to Elasticsearch: {}: body={}",
                        status,
                        body.unwrap_or_default()
                    );
                    false
                }
            }
            Err(err) => {
                error!("Failed to connect to Elasticsearch: {}", err);
                false
            }
        };

        if !success {
            if inquire::Confirm::new("Retry?")
                .with_default(true)
                .prompt_skippable()?
                .unwrap_or_default()
            {
                continue;
            } else {
                return Ok(());
            }
        } else {
            context.config.evebox_server.elasticsearch_client.url = Some(url);
            context.config.evebox_server.elasticsearch_client.index = Some(index);
            context.config.evebox_server.elasticsearch_client.username = if username.is_empty() {
                None
            } else {
                Some(username)
            };
            context.config.evebox_server.elasticsearch_client.password = if password.is_empty() {
                None
            } else {
                Some(password)
            };
            context
                .config
                .evebox_server
                .elasticsearch_client
                .disable_certificate_validation = disable_certificate_validation;
            crate::prompt::enter();
            break;
        }
    }

    context.config.save()?;

    Ok(())
}
