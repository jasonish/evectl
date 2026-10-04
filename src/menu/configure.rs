// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The top-level Configure menu. Shared submenus are reached through the
//! platform backend, which also contributes platform-only options.

use crate::prelude::*;

use crate::prompt::Selections;
use crate::{context::Context, term};

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

/// Linux Configure menu backed by the container runtime.
pub(crate) fn main(context: &mut Context) -> Result<()> {
    let mut backend = ContainerBackend {
        runtime: context.clone(),
    };
    menu(&mut context.config, &mut backend)
}

pub(crate) fn menu(config: &mut Config, backend: &mut dyn Backend) -> Result<()> {
    loop {
        term::clear();
        let selections = menu_options(config, backend);
        let selection = match inquire::Select::new("EveCtl: Configure", selections.to_vec())
            .with_page_size(selections.page_size())
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
            error!("Configuration failed: {err:#}");
            crate::prompt::enter();
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

/// Submenus that still take a Context edit a runtime snapshot; the caller's
/// configuration is synchronized around each call.
struct ContainerBackend {
    runtime: Context,
}

impl ContainerBackend {
    fn with_context(
        &mut self,
        config: &mut Config,
        action: impl FnOnce(&mut Context) -> Result<()>,
    ) -> Result<()> {
        self.runtime.config = config.clone();
        let result = action(&mut self.runtime);
        *config = self.runtime.config.clone();
        result
    }
}

const CONTAINER_IMAGES: &str = "container-images";
const START_ON_BOOT: &str = "start-on-boot";

impl Backend for ContainerBackend {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_> {
        Box::new(crate::suricata::configuration::ContainerBackend(
            &self.runtime,
        ))
    }

    fn fpc(&self) -> Box<dyn crate::fpc::Backend + '_> {
        Box::new(crate::fpc::ContainerBackend(&self.runtime))
    }

    fn configure_evebox_server(&mut self, config: &mut Config) -> Result<()> {
        crate::menu::evebox_server::menu(
            config,
            &crate::evebox::configuration::ContainerBackend(&self.runtime),
        )
    }

    fn platform_options(&self, _config: &Config) -> Vec<PlatformOption> {
        vec![
            PlatformOption {
                id: CONTAINER_IMAGES,
                label: "Containers Images".to_string(),
            },
            PlatformOption {
                id: START_ON_BOOT,
                label: if crate::systemd::is_enabled() {
                    "Disable Start on Boot".to_string()
                } else {
                    "Enable Start on Boot".to_string()
                },
            },
        ]
    }

    fn run_platform_option(&mut self, config: &mut Config, id: &str) -> Result<()> {
        match id {
            CONTAINER_IMAGES => self.with_context(config, |context| {
                crate::menu::containers::menu(context);
                Ok(())
            }),
            START_ON_BOOT => start_on_boot(&self.runtime),
            _ => bail!("Unknown configuration option: {id}"),
        }
    }
}

pub(crate) fn start_on_boot(context: &Context) -> Result<()> {
    if !crate::systemd::is_enabled() {
        info!("Start on boot is enabled by using sudo to install a systemd service file.");
        if !crate::prompt::confirm("Do you wish to continue?") {
            return Ok(());
        }
        crate::systemd::install(&context.root, context.manager)?;
    } else if crate::prompt::confirm("Do you wish to disable start on boot?")
        && let Err(err) = crate::systemd::remove()
    {
        tracing::error!("Failed to remove systemd unit: {}", err);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
