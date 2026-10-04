// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! EveBox server configuration shared by Linux and Windows. Search engine
//! datastores are only offered when the platform backend supports them.

use crate::prelude::*;

use crate::{
    config::{ElasticsearchConfig, EveBoxServerConfig, SearchEngine},
    evebox::configuration::{Backend, BindAddress},
    prompt::Selections,
    term,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

/// Settings are edited directly in the caller's configuration, which
/// the caller persists.
pub(crate) fn menu(config: &mut Config, backend: &dyn Backend) -> Result<()> {
    loop {
        term::clear();
        let selections = menu_options(config, backend);
        match selections.prompt("EveCtl: Configure EveBox Server")? {
            None | Some(Options::Return) => break,
            Some(action) => crate::prompt::report(
                "EveBox server configuration failed",
                run_action(config, backend, action),
            ),
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
                    config.elasticsearch.memory_gb()
                ),
            );
        }
    }

    selections.push(Options::ResetPassword, "Reset Admin Password");
    selections.push(Options::Return, "Return");
    selections
}

fn run_action(config: &mut Config, backend: &dyn Backend, action: Options) -> Result<()> {
    let server = &mut config.evebox_server;
    match action {
        Options::EnableToggle => server.enabled = !server.enabled,
        Options::ToggleTls => toggle_guarded(&mut server.no_tls, server.allow_remote, "TLS"),
        Options::ToggleAuth => {
            toggle_guarded(&mut server.no_auth, server.allow_remote, "authentication")
        }
        Options::ResetPassword => backend.reset_password()?,
        Options::EnableRemote => enable_remote_access(server, backend)?,
        Options::DisableRemote => server.allow_remote = false,
        Options::SetBindAddress => set_bind_address(server, backend)?,
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

/// Prompt for a datastore, returning None if the prompt was
/// cancelled.
pub(crate) fn select_datastore(include_external: bool) -> Result<Option<Datastore>> {
    let mut selections = Selections::new();
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
    selections.prompt_with("Which datastore should EveBox use?", |select| {
        select.with_help_message(
            "SQLite is suitable for most systems, OpenSearch and Elasticsearch require more memory",
        )
    })
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
        .with_default(config.elasticsearch.memory_gb())
        .with_help_message("The search engine will use half of this for its heap. ESC to cancel.")
        .prompt_skippable()?;
    match memory {
        None => {}
        Some(0) => {
            error!("Memory limit must be at least 1GB");
            crate::prompt::enter();
        }
        Some(memory) => {
            config.elasticsearch.memory = if memory == ElasticsearchConfig::DEFAULT_MEMORY_GB {
                None
            } else {
                Some(memory)
            };
        }
    }
    Ok(())
}

/// Toggle a "disabled" flag for a protection (TLS or authentication),
/// confirming before disabling it while remote access is allowed.
fn toggle_guarded(disabled: &mut bool, allow_remote: bool, what: &str) {
    if *disabled {
        *disabled = false;
    } else if !allow_remote
        || crate::prompt::confirm_destructive(&format!(
            "Remote access is enabled, are you sure you want to disable {what}"
        ))
    {
        *disabled = true;
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

/// Bind address choices: all interfaces (None) first, then each IPv4
/// address.
fn bind_address_options(addresses: &[BindAddress]) -> Selections<Option<String>> {
    let mut options = Selections::new();
    options.push(None, "All interfaces");
    for address in addresses {
        options.push(
            Some(address.address.clone()),
            format!("{} ({})", address.address, address.interface),
        );
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
    if let Some(address) = options.prompt_with("Select address to bind to:", |select| {
        select.with_starting_cursor(cursor)
    })? {
        config.bind_address = address;
    }
    Ok(())
}

/// Collect and test the external search engine connection; the caller
/// persists the configuration.
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

        let basic_auth = (!username.is_empty()).then(|| {
            (
                username.as_str(),
                (!password.is_empty()).then_some(password.as_str()),
            )
        });
        match crate::menu::evebox_agent::test_url(&url, !disable_certificate_validation, basic_auth)
        {
            Ok(body) => {
                info!("Connected successfully to Elasticsearch: body={body}");
            }
            Err(err) => {
                error!("Failed to connect to Elasticsearch: {err:#}");
                if crate::prompt::confirm("Retry?") {
                    continue;
                }
                return Ok(());
            }
        }

        let client = &mut config.evebox_server.elasticsearch_client;
        client.url = Some(url);
        client.index = Some(index);
        client.username = (!username.is_empty()).then_some(username);
        client.password = (!password.is_empty()).then_some(password);
        client.disable_certificate_validation = disable_certificate_validation;
        crate::prompt::enter();
        return Ok(());
    }
}

#[cfg(test)]
mod tests;
