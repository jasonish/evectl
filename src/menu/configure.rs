// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The top-level Configure menu. Shared submenus run on the platform,
//! which also contributes platform-only options.

use crate::platform::Platform;
use crate::prelude::*;
use crate::prompt::Selections;
use crate::term;

pub(crate) trait Backend {
    /// The platform behind the shared submenus, brought up to date
    /// with `config`.
    fn platform(&mut self, config: &Config) -> &dyn Platform;
    /// Labels of the platform-only options, shown after the shared ones.
    fn platform_options(&self, config: &Config) -> Vec<String>;
    /// Run the option at `index` of `platform_options` for `config`.
    fn run_platform_option(&mut self, config: &mut Config, index: usize) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Options {
    Suricata,
    EveBoxAgent,
    EveBoxServer,
    Fpc,
    Platform(usize),
    Return,
}

pub(crate) fn menu(config: &mut Config, backend: &mut dyn Backend) -> Result<()> {
    loop {
        term::clear();
        let selections = menu_options(config, backend);
        match selections.prompt("EveCtl: Configure")? {
            None | Some(Options::Return) => break,
            Some(action) => {
                crate::prompt::report("Configuration failed", run_action(config, backend, action))
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
    for (index, label) in backend.platform_options(config).into_iter().enumerate() {
        selections.push(Options::Platform(index), label);
    }
    selections.push(Options::Return, "Return");
    selections
}

fn run_action(config: &mut Config, backend: &mut dyn Backend, action: Options) -> Result<()> {
    match action {
        Options::Suricata => crate::menu::suricata::menu(config, backend.platform(config)),
        Options::EveBoxAgent => crate::menu::evebox_agent::menu(config),
        Options::EveBoxServer => crate::menu::evebox_server::menu(config, backend.platform(config)),
        Options::Fpc => crate::menu::fpc::menu(config, backend.platform(config)),
        Options::Platform(index) => backend.run_platform_option(config, index),
        Options::Return => Ok(()),
    }
}

#[cfg(test)]
mod tests;
