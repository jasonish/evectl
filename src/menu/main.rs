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

pub(crate) trait Backend {
    /// Log the service status lines and report the state.
    fn status(&mut self, config: &Config) -> Status;
    fn save_config(&mut self, config: &Config) -> Result<()> {
        config.save()
    }
    /// Called after a changed configuration was saved. Changes that do
    /// not need a service restart can be copied into `original` so no
    /// restart is offered for them.
    fn acknowledge_saved_changes(&mut self, _original: &mut Config, _current: &Config) {}
    fn start(&mut self, config: &Config) -> Result<()>;
    fn stop(&mut self, config: &Config) -> Result<()>;
    fn restart(&mut self, config: &Config) -> Result<()>;
    fn install(&mut self, config: &mut Config) -> Result<()>;
    fn update_rules(&mut self, config: &Config) -> Result<()>;
    fn rules(&mut self, config: &Config) -> Box<dyn crate::rules::Backend + '_>;
    fn update(&mut self, config: &Config) -> Result<UpdateOutcome>;
    fn configure(&mut self, config: &mut Config) -> Result<()>;
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
        let selection = match inquire::Select::new("Select a menu option", selections.to_vec())
            .with_page_size(12)
            .prompt()
        {
            Ok(selection) => selection,
            Err(_) => break,
        };

        match selection.tag {
            Options::Refresh => {}
            Options::Restart => {
                crate::prompt::report("Failed to restart services", backend.restart(config));
                original = config.clone();
            }
            Options::Stop => crate::prompt::report("Failed to stop services", backend.stop(config)),
            Options::Start => {
                crate::prompt::report("Failed to start services", backend.start(config))
            }
            Options::Install => {
                crate::prompt::report_and_pause("Installation failed", backend.install(config));
                // The wizard saves its own configuration; don't treat it
                // as a pending change needing a restart.
                original = config.clone();
            }
            Options::UpdateRules => crate::prompt::report_and_pause(
                "Failed to update rules",
                backend.update_rules(config),
            ),
            Options::ManageRules => crate::menu::rules::menu(backend.rules(config).as_ref())?,
            Options::Update => match backend.update(config) {
                Ok(UpdateOutcome::ExitMenu) => break,
                Ok(UpdateOutcome::Completed) => crate::prompt::enter(),
                Err(err) => crate::prompt::report_and_pause("Update failed", Err(err)),
            },
            Options::Configure => backend.configure(config)?,
            Options::Other => backend.other(config)?,
            Options::Exit => break,
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
    backend.save_config(config)?;
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
