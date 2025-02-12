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
    ToggleElasticsearch,
    Return,
}

pub(crate) fn menu(context: &mut Context) -> Result<()> {
    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::with_index();

        if context.config.evebox_server.enabled {
            selections.push(Options::EnableToggle, "Disable EveBox Server [enabled]");
        } else {
            selections.push(Options::EnableToggle, "Enable EveBox Server [disabled]");
        }

        if context.config.evebox_server.allow_remote {
            selections.push(Options::DisableRemote, "Disable Remote Access");
        } else {
            selections.push(Options::EnableRemote, "Enable Remote Access");
        }
        selections.push(
            Options::ToggleTls,
            format!(
                "Toggle TLS (Currently {})",
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
                "Toggle authentication (Currently {})",
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
                "Toggle Elasticsearch (Currently {})",
                if context.config.elasticsearch.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
        );

        selections.push(Options::ResetPassword, "Reset Admin Password");
        selections.push(Options::Return, "Return");

        if let Ok(selection) =
            inquire::Select::new("EveCtl: Configure EveBox Server", selections.to_vec()).prompt()
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
                Options::ToggleElasticsearch => toggle_elasticsearch(context),
                Options::Return => break,
            }
        } else {
            break;
        }
    }

    Ok(())
}

fn toggle_elasticsearch(context: &mut Context) {
    context.config.elasticsearch.enabled = !context.config.elasticsearch.enabled;
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
