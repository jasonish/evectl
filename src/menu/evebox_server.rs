// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::{
    config::{EveBoxServerConfig, SearchEngine},
    context::Context,
    term,
};

#[derive(Clone)]
enum Options {
    EnableToggle,
    ToggleTls,
    ToggleAuth,
    ResetPassword,
    EnableRemote,
    DisableRemote,
    SetBindAddress,
    Datastore,
    Memory,
    ElasticsearchUrl,
    Return,
}

/// The datastore choices for the EveBox server.
#[derive(Clone)]
pub(crate) enum Datastore {
    Sqlite,
    OpenSearch,
    Elasticsearch,
    ExternalElasticsearch,
}

impl Datastore {
    pub(crate) fn engine(&self) -> Option<SearchEngine> {
        match self {
            Datastore::OpenSearch => Some(SearchEngine::OpenSearch),
            Datastore::Elasticsearch => Some(SearchEngine::Elasticsearch),
            _ => None,
        }
    }
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
            selections.push(Options::EnableToggle, "Disable EveBox Server [enabled]");
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

        let datastore = if context.config.evebox_server.use_external_elasticsearch {
            "External OpenSearch or Elasticsearch".to_string()
        } else if context.config.elasticsearch.enabled {
            context.config.elasticsearch.engine.name().to_string()
        } else {
            "SQLite".to_string()
        };
        selections.push(Options::Datastore, format!("Datastore [{}]", datastore));

        if context.config.evebox_server.use_external_elasticsearch {
            selections.push(
                Options::ElasticsearchUrl,
                format!(
                    "External Server URL: [{}]",
                    context
                        .config
                        .evebox_server
                        .elasticsearch_client
                        .url
                        .as_deref()
                        .unwrap_or("not set")
                ),
            );
        } else if context.config.elasticsearch.enabled {
            selections.push(
                Options::Memory,
                format!(
                    "{} Memory Limit [{}GB]",
                    context.config.elasticsearch.engine.name(),
                    crate::elastic::memory_gb(context)
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
                Options::Datastore => set_datastore(context)?,
                Options::Memory => set_memory(context)?,
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

/// Prompt for a datastore, returning None if the prompt was
/// cancelled.
pub(crate) fn select_datastore(include_external: bool) -> Result<Option<Datastore>> {
    let mut selections = crate::prompt::Selections::new();
    selections.push(Datastore::Sqlite, "SQLite (recommended)");
    selections.push(Datastore::OpenSearch, "OpenSearch (managed by EveCtl)");
    selections.push(
        Datastore::Elasticsearch,
        "Elasticsearch (managed by EveCtl)",
    );
    if include_external {
        selections.push(
            Datastore::ExternalElasticsearch,
            "External OpenSearch or Elasticsearch",
        );
    }
    let selection = inquire::Select::new("Which datastore should EveBox use?", selections.to_vec())
        .with_help_message(
            "SQLite is suitable for most systems, OpenSearch and Elasticsearch require more memory",
        )
        .prompt_skippable()?;
    Ok(selection.map(|selection| selection.tag))
}

fn set_datastore(context: &mut Context) -> Result<()> {
    let Some(datastore) = select_datastore(true)? else {
        return Ok(());
    };

    let previous = (
        context.config.elasticsearch.enabled,
        context.config.elasticsearch.engine,
        context.config.evebox_server.use_external_elasticsearch,
    );

    if let Datastore::ExternalElasticsearch = datastore {
        context.config.elasticsearch.enabled = false;
        context.config.evebox_server.use_external_elasticsearch = true;
        set_elasticsearch_url(context)?;
    } else {
        context.config.evebox_server.use_external_elasticsearch = false;
        if let Some(engine) = datastore.engine() {
            context.config.elasticsearch.enabled = true;
            context.config.elasticsearch.engine = engine;
        } else {
            context.config.elasticsearch.enabled = false;
        }
    }

    let current = (
        context.config.elasticsearch.enabled,
        context.config.elasticsearch.engine,
        context.config.evebox_server.use_external_elasticsearch,
    );
    if current != previous {
        warn!("Existing events will not be migrated to the new datastore.");
        crate::prompt::enter();
    }

    Ok(())
}

fn set_memory(context: &mut Context) -> Result<()> {
    let memory = inquire::CustomType::<u32>::new("Memory limit in gigabytes:")
        .with_default(crate::elastic::memory_gb(context))
        .with_help_message("The search engine will use half of this for its heap. ESC to cancel.")
        .prompt_skippable()?;
    match memory {
        None => {}
        Some(0) => {
            error!("Memory limit must be at least 1GB");
            crate::prompt::enter();
        }
        Some(memory) => {
            context.config.elasticsearch.memory = if memory == crate::elastic::DEFAULT_MEMORY_GB {
                None
            } else {
                Some(memory)
            };
        }
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

        let client = crate::http::client_builder()
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
