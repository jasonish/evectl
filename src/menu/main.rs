// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The main menu. Service control, installation, and updates are platform
//! specific; the menu owns navigation, configuration persistence, and the
//! restart-after-change flow.

use crate::prelude::*;
use crate::prompt::Selections;
use crate::term;

/// Service state as it affects the menu.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Status {
    /// Any managed service is running: offer Restart and Stop.
    pub(crate) running: bool,
    /// Every enabled service can be started; otherwise offer Install.
    pub(crate) ready_to_start: bool,
    /// EveCtl itself was updated and services should be restarted.
    pub(crate) restart_recommended: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum UpdateOutcome {
    Completed,
    /// EveCtl was replaced; leave the menu without running anything else.
    /// Linux self-updates re-exec instead of returning here.
    #[cfg_attr(not(windows), allow(dead_code))]
    ExitMenu,
}

/// The main menu's platform, which also serves the Configure menu.
pub(crate) trait Backend: crate::menu::configure::Backend {
    /// Log the service status lines and report the state.
    fn status(&mut self, config: &Config) -> Status;
    /// Called after a changed configuration was saved. Changes that do
    /// not need a service restart can be copied into `original` so no
    /// restart is offered for them.
    fn acknowledge_saved_changes(&mut self, _original: &mut Config, _current: &Config) {}
    fn start(&mut self, config: &Config) -> Result<()>;
    fn stop(&mut self, config: &Config) -> Result<()>;
    fn restart(&mut self, config: &Config) -> Result<()>;
    /// Install the components of the enabled services, offered while
    /// the status is not ready to start.
    fn install(&mut self, config: &mut Config) -> Result<()>;
    fn update(&mut self, config: &Config) -> Result<UpdateOutcome>;
    fn other(&mut self, config: &mut Config) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Options {
    Refresh,
    Restart,
    Stop,
    Start,
    Install,
    UpdateRules,
    ManageRules,
    Update,
    Configure,
    Other,
    Exit,
}

pub(crate) fn menu(config: &mut Config, backend: &mut dyn Backend) -> Result<()> {
    let mut original = config.clone();

    loop {
        // Save a changed configuration and offer a restart, and keep
        // offering until a restart happens.
        if save_changes(config, &mut original, backend)?
            && crate::prompt::confirm("Configuration has changed, restart?")
        {
            crate::prompt::report("Failed to restart services", backend.restart(config));
            original = config.clone();
        }

        term::title("EveCtl: Main Menu");
        let status = backend.status(config);
        println!();

        if original != *config {
            warn!("Configuration has changed, restart required");
        }
        if status.restart_recommended {
            warn!(
                "EveCtl was updated. Choosing Restart from this menu to restart all enabled \
                 services is recommended."
            );
        }

        let selections = menu_options(config, status);
        match selections.prompt("Select a menu option")? {
            None | Some(Options::Exit) => break,
            Some(Options::Refresh) => {}
            Some(Options::Restart) => {
                crate::prompt::report("Failed to restart services", backend.restart(config));
                original = config.clone();
            }
            Some(Options::Stop) => {
                crate::prompt::report("Failed to stop services", backend.stop(config))
            }
            Some(Options::Start) => {
                crate::prompt::report("Failed to start services", backend.start(config))
            }
            Some(Options::Install) => {
                crate::prompt::report_and_pause("Installation failed", backend.install(config));
                // The wizard saves its own configuration; don't treat it
                // as a pending change needing a restart.
                original = config.clone();
            }
            Some(Options::UpdateRules) => crate::prompt::report_and_pause(
                "Failed to update rules",
                backend.platform(config).update_rules(),
            ),
            Some(Options::ManageRules) => crate::menu::rules::menu(backend.platform(config))?,
            Some(Options::Update) => match backend.update(config) {
                Ok(UpdateOutcome::ExitMenu) => break,
                Ok(UpdateOutcome::Completed) => crate::prompt::enter(),
                Err(err) => crate::prompt::report_and_pause("Update failed", Err(err)),
            },
            Some(Options::Configure) => crate::menu::configure::menu(config, backend)?,
            Some(Options::Other) => backend.other(config)?,
        }
    }

    Ok(())
}

/// Save a changed configuration. Returns true if the saved changes
/// require a service restart.
fn save_changes(config: &Config, original: &mut Config, backend: &mut dyn Backend) -> Result<bool> {
    if *config == *original {
        return Ok(false);
    }
    config.save()?;
    backend.acknowledge_saved_changes(original, config);
    Ok(*config != *original)
}

fn menu_options(config: &Config, status: Status) -> Selections<Options> {
    let mut selections = Selections::with_index();
    selections.push(Options::Refresh, "Refresh Status");
    if status.running || (status.restart_recommended && status.ready_to_start) {
        selections.push(Options::Restart, "Restart");
    }
    if status.running {
        selections.push(Options::Stop, "Stop");
    } else if status.ready_to_start {
        selections.push(Options::Start, "Start");
    } else {
        selections.push(Options::Install, "Install");
    }
    if config.suricata.enabled {
        selections.push(Options::UpdateRules, "Update Rules");
        selections.push(Options::ManageRules, "Manage Rules");
    }
    selections.push(Options::Update, "Update");
    selections.push(Options::Configure, "Configure");
    selections.push(Options::Other, "Other");
    selections.push(Options::Exit, "Exit");
    selections
}

#[cfg(test)]
mod tests;
