// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! EveBox server configuration shared by Linux and Windows. Search engine
//! datastores are only offered when the platform backend supports them.

use crate::prelude::*;

use crate::{
    config::{EveBoxServerConfig, SearchEngine},
    context::Context,
    evebox::configuration::{Backend, BindAddress, ContainerBackend},
    prompt::Selections,
    term,
};

#[derive(Debug, Clone, Eq, PartialEq)]
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

/// Linux menu backed by the container runtime. Settings are edited
/// directly in the caller's configuration.
pub(crate) fn container_menu(context: &mut Context) -> Result<()> {
    let runtime = context.clone();
    menu(&mut context.config, &ContainerBackend(&runtime))
}

pub(crate) fn menu(config: &mut Config, backend: &dyn Backend) -> Result<()> {
    loop {
        term::clear();
        let selections = menu_options(config, backend);
        let selection =
            match inquire::Select::new("EveCtl: Configure EveBox Server", selections.to_vec())
                .with_page_size(16)
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
        if let Err(err) = run_action(config, backend, &selection.tag) {
            error!("EveBox server configuration failed: {err:#}");
            crate::prompt::enter();
        }
    }
    Ok(())
}

fn menu_options(config: &Config, backend: &dyn Backend) -> Selections<Options> {
    let mut selections = Selections::with_index();
    let server = &config.evebox_server;

    if server.enabled {
        selections.push(Options::EnableToggle, "Disable EveBox Server [enabled]");
    } else {
        selections.push(Options::EnableToggle, "Enable EveBox Server [disabled]");
    }

    if server.allow_remote {
        selections.push(Options::DisableRemote, "Disable Remote Access [enabled]");
        let bind_label = if let Some(value) = &server.bind_address {
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
            if server.no_tls { "disabled" } else { "enabled" }
        ),
    );
    selections.push(
        Options::ToggleAuth,
        format!(
            "Toggle authentication [{}]",
            if server.no_auth {
                "disabled"
            } else {
                "enabled"
            }
        ),
    );

    if backend.supports_search_engines() {
        let datastore = if server.use_external_elasticsearch {
            "External OpenSearch or Elasticsearch".to_string()
        } else if config.elasticsearch.enabled {
            config.elasticsearch.engine.name().to_string()
        } else {
            "SQLite".to_string()
        };
        selections.push(Options::Datastore, format!("Datastore [{}]", datastore));

        if server.use_external_elasticsearch {
            selections.push(
                Options::ElasticsearchUrl,
                format!(
                    "External Server URL: [{}]",
                    server
                        .elasticsearch_client
                        .url
                        .as_deref()
                        .unwrap_or("not set")
                ),
            );
        } else if config.elasticsearch.enabled {
            selections.push(
                Options::Memory,
                format!(
                    "{} Memory Limit [{}GB]",
                    config.elasticsearch.engine.name(),
                    memory_gb(config)
                ),
            );
        }
    }

    selections.push(Options::ResetPassword, "Reset Admin Password");
    selections.push(Options::Return, "Return");
    selections
}

fn run_action(config: &mut Config, backend: &dyn Backend, action: &Options) -> Result<()> {
    match action {
        Options::EnableToggle => {
            config.evebox_server.enabled = !config.evebox_server.enabled;
        }
        Options::ToggleTls => toggle_tls(&mut config.evebox_server),
        Options::ToggleAuth => toggle_auth(&mut config.evebox_server),
        Options::ResetPassword => backend.reset_password()?,
        Options::EnableRemote => enable_remote_access(&mut config.evebox_server, backend)?,
        Options::DisableRemote => config.evebox_server.allow_remote = false,
        Options::SetBindAddress => set_bind_address(&mut config.evebox_server, backend)?,
        Options::Datastore | Options::Memory | Options::ElasticsearchUrl
            if !backend.supports_search_engines() =>
        {
            bail!("Search engine datastores are not supported on this platform");
        }
        Options::Datastore => set_datastore(config)?,
        Options::Memory => set_memory(config)?,
        Options::ElasticsearchUrl => set_elasticsearch_url(config)?,
        Options::Return => {}
    }
    Ok(())
}

fn memory_gb(config: &Config) -> u32 {
    config
        .elasticsearch
        .memory
        .unwrap_or(crate::elastic::DEFAULT_MEMORY_GB)
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

fn set_datastore(config: &mut Config) -> Result<()> {
    let Some(datastore) = select_datastore(true)? else {
        return Ok(());
    };

    let previous = (
        config.elasticsearch.enabled,
        config.elasticsearch.engine,
        config.evebox_server.use_external_elasticsearch,
    );

    if let Datastore::ExternalElasticsearch = datastore {
        config.elasticsearch.enabled = false;
        config.evebox_server.use_external_elasticsearch = true;
        set_elasticsearch_url(config)?;
    } else {
        config.evebox_server.use_external_elasticsearch = false;
        if let Some(engine) = datastore.engine() {
            config.elasticsearch.enabled = true;
            config.elasticsearch.engine = engine;
        } else {
            config.elasticsearch.enabled = false;
        }
    }

    let current = (
        config.elasticsearch.enabled,
        config.elasticsearch.engine,
        config.evebox_server.use_external_elasticsearch,
    );
    if current != previous {
        warn!("Existing events will not be migrated to the new datastore.");
        crate::prompt::enter();
    }

    Ok(())
}

fn set_memory(config: &mut Config) -> Result<()> {
    let memory = inquire::CustomType::<u32>::new("Memory limit in gigabytes:")
        .with_default(memory_gb(config))
        .with_help_message("The search engine will use half of this for its heap. ESC to cancel.")
        .prompt_skippable()?;
    match memory {
        None => {}
        Some(0) => {
            error!("Memory limit must be at least 1GB");
            crate::prompt::enter();
        }
        Some(memory) => {
            config.elasticsearch.memory = if memory == crate::elastic::DEFAULT_MEMORY_GB {
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
        if config.allow_remote
            && !crate::prompt::confirm_destructive(
                "Remote access is enabled, are you sure you want to disable TLS",
            )
        {
            return;
        }
        config.no_tls = true;
    }
}

fn toggle_auth(config: &mut EveBoxServerConfig) {
    if config.no_auth {
        config.no_auth = false;
    } else {
        if config.allow_remote
            && !crate::prompt::confirm_destructive(
                "Remote access is enabled, are you sure you want to disable authentication",
            )
        {
            return;
        }
        config.no_auth = true;
    }
}

/// Remote access re-enables TLS and authentication, then offers a
/// password reset so the admin password is known.
fn enable_remote_access(config: &mut EveBoxServerConfig, backend: &dyn Backend) -> Result<()> {
    if config.no_tls {
        warn!("Enabling TLS");
        config.no_tls = false;
    }
    if config.no_auth {
        warn!("Enabling authentication");
        config.no_auth = false;
    }
    config.allow_remote = true;

    if crate::prompt::confirm("Do you wish to reset the admin password") {
        backend.reset_password()?;
    }
    Ok(())
}

/// Bind address choices: all interfaces first, then each IPv4 address.
fn bind_address_options(addresses: &[BindAddress]) -> Vec<BindAddressOption> {
    let mut options = vec![BindAddressOption {
        label: "All interfaces".to_string(),
        address: None,
    }];
    for address in addresses {
        options.push(BindAddressOption {
            label: format!("{} ({})", address.address, address.interface),
            address: Some(address.address.clone()),
        });
    }
    options
}

/// Index of the current bind value, which may be an address or an
/// interface name, defaulting to all interfaces.
fn bind_address_cursor(addresses: &[BindAddress], current: Option<&str>) -> usize {
    let Some(current) = current else {
        return 0;
    };
    let position = if current.parse::<std::net::IpAddr>().is_ok() {
        addresses.iter().position(|a| a.address == current)
    } else {
        addresses.iter().position(|a| a.interface == current)
    };
    position.map(|i| i + 1).unwrap_or(0)
}

fn set_bind_address(config: &mut EveBoxServerConfig, backend: &dyn Backend) -> Result<()> {
    let addresses = backend
        .bind_addresses()
        .context("Failed to get network interfaces")?;
    if addresses.is_empty() {
        bail!("No network interfaces with IPv4 addresses found");
    }

    let options = bind_address_options(&addresses);
    let cursor = bind_address_cursor(&addresses, config.bind_address.as_deref());
    if let Ok(selection) = inquire::Select::new("Select address to bind to:", options)
        .with_starting_cursor(cursor)
        .prompt()
    {
        config.bind_address = selection.address;
    }
    Ok(())
}

fn set_elasticsearch_url(config: &mut Config) -> Result<()> {
    let client = &config.evebox_server.elasticsearch_client;
    let mut url = client.url.clone().unwrap_or_default();
    let mut index = client.index.clone().unwrap_or_else(|| "evebox".to_string());
    let mut username = client.username.clone().unwrap_or_default();
    let mut password = client.password.clone().unwrap_or_default();

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
            crate::prompt::ask("Disable certificate validation?", false)?
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
            if crate::prompt::confirm("Retry?") {
                continue;
            } else {
                return Ok(());
            }
        } else {
            let client = &mut config.evebox_server.elasticsearch_client;
            client.url = Some(url);
            client.index = Some(index);
            client.username = if username.is_empty() {
                None
            } else {
                Some(username)
            };
            client.password = if password.is_empty() {
                None
            } else {
                Some(password)
            };
            client.disable_certificate_validation = disable_certificate_validation;
            crate::prompt::enter();
            break;
        }
    }

    config.save()?;

    Ok(())
}

#[cfg(test)]
mod tests;
