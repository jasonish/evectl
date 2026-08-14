// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use crate::{context::Context, term};

#[derive(Clone)]
enum Options {
    ContainerImages,
    Suricata,
    Return,
    EveBoxAgent,
    EveBoxServer,
    StartOnBoot,
}

/// Main configure menu.
pub(crate) fn main(context: &mut Context) -> Result<()> {
    loop {
        term::clear();

        let mut selections = crate::prompt::Selections::with_index();

        let interface = context
            .config
            .suricata
            .interfaces
            .first()
            .map(String::from)
            .unwrap_or_default();
        selections.push(
            Options::Suricata,
            format!(
                "Configure Suricata [enabled={}, interface={}]",
                context.config.suricata.enabled,
                if interface.is_empty() {
                    "None"
                } else {
                    &interface
                }
            ),
        );

        selections.push(
            Options::EveBoxAgent,
            format!(
                "Configure EveBox Agent [enabled={}]",
                context.config.evebox_agent.enabled
            ),
        );

        selections.push(
            Options::EveBoxServer,
            format!(
                "Configure EveBox Server [enabled={}]",
                context.config.evebox_server.enabled
            ),
        );

        selections.push(Options::ContainerImages, "Containers Images");

        if crate::systemd::is_enabled() {
            selections.push(Options::StartOnBoot, "Disable Start on Boot");
        } else {
            selections.push(Options::StartOnBoot, "Enable Start on Boot");
        }

        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure", selections.to_vec()).prompt() {
            Ok(selection) => match selection.tag {
                Options::ContainerImages => crate::menu::containers::menu(context),
                Options::Suricata => crate::menu::suricata::menu(context)?,
                Options::EveBoxAgent => crate::menu::evebox_agent::menu(context)?,
                Options::EveBoxServer => crate::menu::evebox_server::menu(context)?,
                Options::StartOnBoot => start_on_boot()?,
                Options::Return => return Ok(()),
            },
            Err(_) => break,
        }
    }

    Ok(())
}

pub(crate) fn start_on_boot() -> Result<()> {
    if !crate::systemd::is_enabled() {
        info!("Start on boot is enabled by using sudo to install a systemd service file.");
        if !inquire::Confirm::new("Do you wish to continue?")
            .with_default(true)
            .prompt()?
        {
            return Ok(());
        }
        crate::systemd::install()?;
    } else if inquire::Confirm::new("Do you wish to disable start on boot?")
        .with_default(true)
        .prompt()?
    {
        crate::systemd::remove();
    }
    Ok(())
}
