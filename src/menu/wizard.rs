// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use colored::Colorize;

use crate::{container::Container, prelude::*};

#[derive(Debug, Clone)]
enum InstallType {
    Standalone,
    Agent,
    Server,
    Custom,
    Help,
}

pub(crate) fn wizard(context: &mut Context) -> Result<()> {
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

    let install_type;
    loop {
        let selection = inquire::Select::new(
            "What type of installation would you like to initialize?",
            selections.to_vec(),
        )
        .prompt()?;

        install_type = match selection.tag {
            InstallType::Standalone => selection.tag,
            InstallType::Agent => selection.tag,
            InstallType::Server => selection.tag,
            InstallType::Custom => return Ok(()),
            InstallType::Help => {
                install_type_help();
                continue;
            }
        };

        break;
    }

    let has_suricata = matches!(install_type, InstallType::Standalone | InstallType::Agent);
    let has_server = matches!(install_type, InstallType::Standalone | InstallType::Server);

    // Ask all questions up front, before any downloads.

    // Suricata questions.
    if has_suricata {
        let interface = super::suricata::select_interface(
            "Suricata: What network interface should Suricata listen on?",
        )?;
        context.config.suricata.enabled = true;
        context.config.suricata.interfaces = vec![interface];
    }

    // EveBox agent questions.
    if let InstallType::Agent = install_type {
        loop {
            if let Some((url, disable_certificate_validation)) =
                crate::menu::evebox_agent::prompt_for_server_url(&context.config)?
            {
                context.config.evebox_agent.enabled = true;
                context.config.evebox_agent.server = url;
                context.config.evebox_agent.disable_certificate_validation =
                    disable_certificate_validation;
                break;
            }
        }
    }

    // EveBox server questions.
    if has_server {
        let use_elasticsearch =
            inquire::Confirm::new("EveBox Server: Use bundled Elasticsearch server?")
                .with_default(false)
                .with_help_message("Recommended for larger systems, avoid if memory is limited")
                .prompt()?;

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

        context.config.evebox_server.enabled = true;
        context.config.evebox_server.allow_remote = allow_remote;
        context.config.evebox_server.no_tls = disable_https;
        context.config.evebox_server.no_auth = disable_auth;

        if use_elasticsearch {
            context.config.elasticsearch.enabled = true;
        }
    }

    if !inquire::Confirm::new("Would you like to proceed with this configuration?")
        .with_default(true)
        .prompt()?
    {
        bail!("Aborting configuration wizard. Bye!");
    }

    // Questions done, on to the downloads. The configuration is not
    // saved until initialization completes so a failure here results
    // in the wizard being run again on next start.

    if has_suricata {
        info!("Pulling Suricata image...");
        context
            .manager
            .pull(&context.image_name(Container::Suricata))?;
    }

    info!("Pulling EveBox image...");
    context
        .manager
        .pull(&context.image_name(Container::EveBox))?;

    if context.config.elasticsearch.enabled {
        info!("Pulling Elasticsearch image...");
        context.manager.pull(crate::elastic::DOCKER_IMAGE)?;
    }

    if has_suricata {
        info!("Updating Suricata rules...");
        crate::suricata::mkdirs(context)?;
        crate::actions::update_rules(context, &["--no-reload", "--no-test"])?;
    }

    if has_server && !context.config.evebox_server.no_auth {
        crate::prompt::enter_with_prefix(
            "EveBox Server: When prompted, enter the password for the EveBox \"admin\" user.",
        );
        crate::evebox::server::reset_password(context);
    }

    context.config.save()?;

    Ok(())
}

fn install_type_help() {
    let msg = format!(
        "
{:11      } Suricata and EveBox all-in-one. Suitable for single
            host deployments, or if you come from Simple-IDS. You
            have the choice of using SQLite or Elasticsearch.

{:11      } Suricata and EveBox Agent. Useful if you already 
            have an EveBox server and need to deploy another
            Suricata instance.

{:11      } EveBox server only. Choice of SQLite or Elasticsearch.

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
