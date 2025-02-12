// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use anyhow::Result;

use crate::{context::Context, term};

#[derive(Clone)]
enum Options {
    ContainerImages,
    Suricata,
    Return,
    EveBoxAgent,
    EveBoxServer,
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

        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure", selections.to_vec()).prompt() {
            Ok(selection) => match selection.tag {
                Options::ContainerImages => crate::menu::containers::menu(context),
                Options::Suricata => crate::menu::suricata::menu(context)?,
                Options::EveBoxAgent => crate::menu::evebox_agent::menu(context)?,
                Options::EveBoxServer => crate::menu::evebox_server::menu(context)?,
                Options::Return => return Ok(()),
            },
            Err(_) => break,
        }
    }

    Ok(())
}
