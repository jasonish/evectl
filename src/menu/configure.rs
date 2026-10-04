// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The top-level Configure menu. Shared submenus are reached through the
//! platform backend, which also contributes platform-only options.

use crate::prelude::*;

use crate::prompt::Selections;
use crate::term;

/// A platform-only Configure option, shown after the shared options.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PlatformOption {
    pub(crate) id: &'static str,
    pub(crate) label: String,
}

pub(crate) trait Backend {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_>;
    fn fpc(&self) -> Box<dyn crate::fpc::Backend + '_>;
    fn configure_evebox_server(&mut self, config: &mut Config) -> Result<()>;
    fn platform_options(&self, config: &Config) -> Vec<PlatformOption>;
    fn run_platform_option(&mut self, config: &mut Config, id: &str) -> Result<()>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Options {
    Suricata,
    EveBoxAgent,
    EveBoxServer,
    Fpc,
    Platform(&'static str),
    Return,
}

pub(crate) fn menu(config: &mut Config, backend: &mut dyn Backend) -> Result<()> {
    loop {
        term::clear();
        let selections = menu_options(config, backend);
        match selections.prompt("EveCtl: Configure")? {
            None | Some(Options::Return) => break,
            Some(action) => {
                crate::prompt::report("Configuration failed", run_action(config, backend, &action))
            }
        }
    }
    Ok(())
}

fn menu_options(config: &Config, backend: &dyn Backend) -> Selections<Options> {
    let mut selections = Selections::with_index();

    let interface = config
        .suricata
        .interfaces
        .first()
        .map(String::as_str)
        .unwrap_or_default();
    selections.push(
        Options::Suricata,
        format!(
            "Configure Suricata [enabled={}, interface={}]",
            config.suricata.enabled,
            if interface.is_empty() {
                "None"
            } else {
                interface
            }
        ),
    );
    selections.push(
        Options::EveBoxAgent,
        format!(
            "Configure EveBox Agent [enabled={}]",
            config.evebox_agent.enabled
        ),
    );
    selections.push(
        Options::EveBoxServer,
        format!(
            "Configure EveBox Server [enabled={}]",
            config.evebox_server.enabled
        ),
    );
    selections.push(
        Options::Fpc,
        format!(
            "Configure Full Packet Capture [enabled={}]",
            config.fpc.enabled
        ),
    );
    for option in backend.platform_options(config) {
        selections.push(Options::Platform(option.id), option.label);
    }
    selections.push(Options::Return, "Return");
    selections
}

fn run_action(config: &mut Config, backend: &mut dyn Backend, action: &Options) -> Result<()> {
    match action {
        Options::Suricata => crate::menu::suricata::menu(config, backend.suricata().as_ref()),
        Options::EveBoxAgent => crate::menu::evebox_agent::menu(config),
        Options::EveBoxServer => backend.configure_evebox_server(config),
        Options::Fpc => crate::menu::fpc::menu(config, backend.fpc().as_ref()),
        Options::Platform(id) => backend.run_platform_option(config, id),
        Options::Return => Ok(()),
    }
}

#[cfg(test)]
mod tests;
