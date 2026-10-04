// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! First-run setup wizard shared by Linux and Windows: choose an
//! installation type, answer all questions up front, then install.

use colored::Colorize;

use crate::{container::Container, prelude::*};

pub(crate) trait Backend {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_>;
    fn evebox_server(&self) -> Box<dyn crate::evebox::configuration::Backend + '_>;
    /// Platform questions asked after the shared ones. Returns false if
    /// the user backed out.
    fn platform_questions(&mut self, _config: &mut Config) -> Result<bool> {
        Ok(true)
    }
    /// Download or install the components for the enabled services.
    fn install(&mut self, config: &Config) -> Result<()>;
    fn update_rules(&mut self, config: &Config) -> Result<()>;
    fn save_config(&mut self, config: &Config) -> Result<()> {
        config.save()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum InstallType {
    Standalone,
    Agent,
    Server,
    Custom,
    Help,
}

/// Linux wizard backed by the container runtime.
pub(crate) fn wizard(context: &mut Context) -> Result<()> {
    let mut backend = ContainerBackend {
        runtime: context.clone(),
    };
    menu(&mut context.config, &mut backend)
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

    let search_engines = backend.evebox_server().supports_search_engines();
    let install_type = loop {
        let selection = match inquire::Select::new(
            "What type of installation would you like to initialize?",
            selections.to_vec(),
        )
        .prompt()
        {
            Ok(selection) => selection,
            // Treat ESC like Custom: manual configuration.
            Err(_) => return Ok(()),
        };
        match selection.tag {
            InstallType::Custom => return Ok(()),
            InstallType::Help => install_type_help(search_engines),
            install_type => break install_type,
        }
    };

    let has_suricata = matches!(install_type, InstallType::Standalone | InstallType::Agent);
    let has_server = matches!(install_type, InstallType::Standalone | InstallType::Server);

    // Ask all questions up front, before any downloads.

    if has_suricata {
        let interface = super::suricata::select_interface_from(
            "Suricata: What network interface should Suricata listen on?",
            backend.suricata().interfaces()?,
        )?;
        config.suricata.enabled = true;
        config.suricata.interfaces = vec![interface];
    }

    if install_type == InstallType::Agent {
        loop {
            if let Some((url, disable_certificate_validation)) =
                crate::menu::evebox_agent::prompt_for_server_url(config)?
            {
                config.evebox_agent.enabled = true;
                config.evebox_agent.server = url;
                config.evebox_agent.disable_certificate_validation = disable_certificate_validation;
                break;
            }
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

        let allow_remote = inquire::Confirm::new("EveBox Server: Allow remote access?")
            .with_default(false)
            .with_help_message("Enable to allow access from hosts other than localhost")
            .prompt()?;
        let disable_https = inquire::Confirm::new("EveBox Server: Disable HTTPS?")
            .with_default(false)
            .with_help_message("Disable HTTPS, not recommended if remote-access is allowed")
            .prompt()?;
        let disable_auth = inquire::Confirm::new("EveBox Server: Disable authentication?")
            .with_default(false)
            .with_help_message(
                "Disable authentication, not recommended if remote-access is allowed",
            )
            .prompt()?;

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

    if !inquire::Confirm::new("Would you like to proceed with this configuration?")
        .with_default(true)
        .prompt()?
    {
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
        if let Err(err) = backend.evebox_server().reset_password() {
            error!("Failed to set the EveBox admin password: {err:#}");
            info!("Reset it later from Configure > Configure EveBox Server");
            crate::prompt::enter();
        }
    }

    backend.save_config(config)?;

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

/// The runtime snapshot's configuration is synchronized from the
/// wizard's before each action.
struct ContainerBackend {
    runtime: Context,
}

impl ContainerBackend {
    fn context(&mut self, config: &Config) -> &Context {
        if self.runtime.config != *config {
            self.runtime.config = config.clone();
        }
        &self.runtime
    }
}

impl Backend for ContainerBackend {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_> {
        Box::new(crate::suricata::configuration::ContainerBackend(
            &self.runtime,
        ))
    }

    fn evebox_server(&self) -> Box<dyn crate::evebox::configuration::Backend + '_> {
        Box::new(crate::evebox::configuration::ContainerBackend(
            &self.runtime,
        ))
    }

    fn install(&mut self, config: &Config) -> Result<()> {
        let context = self.context(config);
        if config.suricata.enabled {
            info!("Pulling Suricata image...");
            context
                .manager
                .pull(&context.image_name(Container::Suricata))?;
        }

        info!("Pulling EveBox image...");
        context
            .manager
            .pull(&context.image_name(Container::EveBox))?;

        if config.elasticsearch_enabled() {
            info!("Pulling {} image...", config.elasticsearch.engine.name());
            context
                .manager
                .pull(crate::elastic::docker_image(context))?;
        }
        Ok(())
    }

    fn update_rules(&mut self, config: &Config) -> Result<()> {
        let context = self.context(config);
        crate::suricata::mkdirs(context)?;
        crate::rules::update_rules(context, &["--no-reload", "--no-test"])
    }
}
