// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! First-run setup wizard shared by Linux and Windows: choose an
//! installation type, answer all questions up front, then install.

use colored::Colorize;

use crate::platform::Platform;
use crate::prelude::*;

pub(crate) trait Backend {
    /// The platform, brought up to date with `config`.
    fn platform(&mut self, config: &Config) -> &dyn Platform;
    /// Platform questions asked after the shared ones. Returns false if
    /// the user backed out.
    fn platform_questions(&mut self, _config: &mut Config) -> Result<bool> {
        Ok(true)
    }
    /// Download or install the components for the enabled services.
    fn install(&mut self, config: &Config) -> Result<()>;
    /// The first rule update, before Suricata has ever started.
    fn update_rules(&mut self, config: &Config) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum InstallType {
    Standalone,
    Agent,
    Server,
    Custom,
    Help,
}

pub(crate) fn menu(config: &mut Config, backend: &mut dyn Backend) -> Result<()> {
    let mut selections = crate::prompt::Selections::new();
    selections.push(
        InstallType::Standalone,
        "Standalone: Suricata + EveBox Server",
    );
    selections.push(InstallType::Agent, "Agent:      Suricata + EveBox Agent");
    selections.push(InstallType::Server, "Server:     EveBox server only");
    selections.push(
        InstallType::Custom,
        "Custom:     Exit the wizard and perform manual configuration",
    );
    selections.push(InstallType::Help, "Help:       Show help");

    let search_engines = backend.platform(config).supports_search_engines();
    let install_type = loop {
        match selections.prompt("What type of installation would you like to initialize?")? {
            // Treat ESC like Custom: manual configuration.
            None | Some(InstallType::Custom) => return Ok(()),
            Some(InstallType::Help) => install_type_help(search_engines),
            Some(install_type) => break install_type,
        }
    };

    let has_suricata = matches!(install_type, InstallType::Standalone | InstallType::Agent);
    let has_server = matches!(install_type, InstallType::Standalone | InstallType::Server);

    // Ask all questions up front, before any downloads.

    if has_suricata {
        let interface = super::suricata::select_interface_from(
            "Suricata: What network interface should Suricata listen on?",
            backend.platform(config).interfaces()?,
        )?;
        config.suricata.enabled = true;
        config.suricata.interfaces = vec![interface];
    }

    if install_type == InstallType::Agent {
        loop {
            // A server URL is required; ask again until one is given.
            let Some((url, disable_certificate_validation)) =
                crate::menu::evebox_agent::prompt_for_server_url(config)?
            else {
                bail!("Aborting configuration wizard. Bye!");
            };
            if url.is_empty() {
                continue;
            }
            config.evebox_agent.enabled = true;
            config.evebox_agent.server = url;
            config.evebox_agent.disable_certificate_validation = disable_certificate_validation;
            break;
        }
    }

    if has_server {
        let datastore = if search_engines {
            match crate::menu::evebox_server::select_datastore(false)? {
                Some(datastore) => Some(datastore),
                None => bail!("Aborting configuration wizard. Bye!"),
            }
        } else {
            None
        };

        let allow_remote = crate::prompt::ask_with_help(
            "EveBox Server: Allow remote access?",
            false,
            "Enable to allow access from hosts other than localhost",
        )?;
        let disable_https = crate::prompt::ask_with_help(
            "EveBox Server: Disable HTTPS?",
            false,
            "Disable HTTPS, not recommended if remote-access is allowed",
        )?;
        let disable_auth = crate::prompt::ask_with_help(
            "EveBox Server: Disable authentication?",
            false,
            "Disable authentication, not recommended if remote-access is allowed",
        )?;

        config.evebox_server.enabled = true;
        config.evebox_server.allow_remote = allow_remote;
        config.evebox_server.no_tls = disable_https;
        config.evebox_server.no_auth = disable_auth;

        if let Some(engine) = datastore.and_then(|datastore| datastore.engine()) {
            config.elasticsearch.enabled = true;
            config.elasticsearch.engine = engine;
        }
    }

    if !backend.platform_questions(config)? {
        return Ok(());
    }

    if !crate::prompt::ask("Would you like to proceed with this configuration?", true)? {
        bail!("Aborting configuration wizard. Bye!");
    }

    // Questions done, on to the installation. The configuration is not
    // saved until installation completes so a failure here results in
    // the wizard being run again on next start.

    backend.install(config)?;

    if has_suricata {
        info!("Updating Suricata rules...");
        backend.update_rules(config)?;
    }

    if has_server && !config.evebox_server.no_auth {
        crate::prompt::enter_with_prefix(
            "EveBox Server: When prompted, enter the password for the EveBox \"admin\" user.",
        );
        if let Err(err) = backend.platform(config).reset_password() {
            error!("Failed to set the EveBox admin password: {err:#}");
            info!("Reset it later from Configure > Configure EveBox Server");
            crate::prompt::enter();
        }
    }

    config.save()?;

    Ok(())
}

fn install_type_help(search_engines: bool) {
    let datastores = if search_engines {
        "Choice of SQLite, OpenSearch or Elasticsearch."
    } else {
        "Events are stored in SQLite."
    };
    let msg = format!(
        "
{:11      } Suricata and EveBox all-in-one. Suitable for single
            host deployments. {datastores}

{:11      } Suricata and EveBox Agent. Useful if you already
            have an EveBox server and need to deploy another
            Suricata instance.

{:11      } EveBox server only. {datastores}

{:11      } Exit the wizard and perform manual configuration.
",
        "Standalone:".cyan(),
        "Agent:".blue(),
        "Server:".green(),
        "Custom:".yellow()
    );
    println!("{}", msg);
    crate::prompt::enter();
}
