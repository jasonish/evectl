// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The Windows platform behind the shared menus, where each service
//! runs as a managed background process.

use std::path::PathBuf;

use super::evebox::reset_evebox_admin_password;
use super::install::{
    add_shortcuts, install_configured_components, install_with, upgrade_windows_components,
};
use super::interfaces::windows_interfaces;
use super::menu::{log_status, other_menu, prompt_for_evebox_channel};
use super::paths::Paths;
use super::rules::{
    disable_ruleset, enable_ruleset, suricatax_paths, update_rules, update_sources,
};
use super::runtime::{Role, list_named_processes, managed_process_is_running};
use super::stack::{WindowsStatus, restart_stack, start_stack, stop_stack, windows_status};
use crate::menu::main::{Status, UpdateOutcome};
use crate::platform::Platform;
use crate::prelude::*;
use suricatax_rules::cli as suricatax_cli;
use suricatax_rules::sources::SourceManager;

pub(super) struct WindowsPlatform<'a> {
    pub(super) paths: &'a Paths,
}

impl crate::suricata::configuration::Backend for WindowsPlatform<'_> {
    fn interfaces(&self) -> Result<Vec<crate::suricata::configuration::Interface>> {
        Ok(windows_interfaces()?
            .into_iter()
            .map(|interface| crate::suricata::configuration::Interface {
                name: interface.name,
                address: (!interface.ip_address.is_empty()).then_some(interface.ip_address),
            })
            .collect())
    }

    fn eve_outputs(&self) -> &'static [crate::config::EveOutput] {
        &[crate::config::EveOutput::File]
    }

    fn filestore_dir(&self) -> Result<PathBuf> {
        Ok(self.paths.suricata_filestore_dir())
    }

    fn check_remove_extracted_files(&self) -> Result<()> {
        if !list_named_processes("suricata")?.is_empty()
            || managed_process_is_running(self.paths, Role::Housekeeper)?
        {
            bail!(
                "Suricata or housekeeping is running; stop services before removing extracted files"
            );
        }
        Ok(())
    }

    fn remove_extracted_files(&self) -> Result<()> {
        self.check_remove_extracted_files()?;
        let directory = self.filestore_dir()?;
        if directory.exists() {
            std::fs::remove_dir_all(&directory)
                .with_context(|| format!("Cannot remove {}", directory.display()))?;
        }
        Ok(())
    }
}

impl crate::fpc::Backend for WindowsPlatform<'_> {
    fn spool_dir(&self) -> Result<PathBuf> {
        Ok(self.paths.suricata_pcap_dir())
    }

    fn check_remove_spool(&self) -> Result<()> {
        if !list_named_processes("suricata")?.is_empty() {
            bail!("Suricata is running; stop services before removing packet captures");
        }
        Ok(())
    }

    fn remove_spool(&self) -> Result<()> {
        self.check_remove_spool()?;
        let directory = self.spool_dir()?;
        if directory.exists() {
            std::fs::remove_dir_all(&directory)
                .with_context(|| format!("Cannot remove {}", directory.display()))?;
        }
        Ok(())
    }
}

impl crate::evebox::configuration::Backend for WindowsPlatform<'_> {
    fn supports_search_engines(&self) -> bool {
        false
    }

    fn bind_addresses(&self) -> Result<Vec<crate::evebox::configuration::BindAddress>> {
        Ok(windows_interfaces()?
            .into_iter()
            .filter(|interface| interface.ip_address.parse::<std::net::Ipv4Addr>().is_ok())
            .map(|interface| crate::evebox::configuration::BindAddress {
                interface: interface.name,
                address: interface.ip_address,
            })
            .collect())
    }

    fn reset_password(&self) -> Result<()> {
        reset_evebox_admin_password(self.paths)
    }
}

impl crate::rules::Backend for WindowsPlatform<'_> {
    fn available_rulesets(&self) -> Result<Vec<crate::rules::Ruleset>> {
        let provider = suricatax_paths(self.paths);
        Ok(SourceManager::new(&provider)
            .get_or_download_index()?
            .sources
            .into_iter()
            .map(|(id, source)| crate::rules::Ruleset {
                id,
                summary: Some(source.summary),
                can_enable: source.obsolete.is_none() && source.parameters.is_none(),
            })
            .collect())
    }

    fn enabled_rulesets(&self) -> Result<Vec<crate::rules::Ruleset>> {
        let provider = suricatax_paths(self.paths);
        let enabled = suricatax_cli::enabled_rulesets(&provider)?;
        if enabled.is_empty() {
            return Ok(vec![]);
        }
        let index = SourceManager::new(&provider)
            .read_local_index()
            .unwrap_or(None);
        Ok(enabled
            .into_iter()
            .map(|id| {
                let summary = index
                    .as_ref()
                    .and_then(|index| index.sources.get(&id))
                    .map(|source| source.summary.clone());
                crate::rules::Ruleset {
                    id,
                    summary,
                    can_enable: false,
                }
            })
            .collect())
    }

    fn enable_ruleset(&self, id: &str) -> Result<()> {
        enable_ruleset(self.paths, Some(id))
    }

    fn disable_ruleset(&self, id: &str) -> Result<()> {
        disable_ruleset(self.paths, id)
    }

    fn update_sources(&self) -> Result<()> {
        update_sources(self.paths)
    }

    fn update_rules(&self) -> Result<()> {
        update_rules(self.paths, false, false)
    }
}

#[derive(Debug, Clone, Copy)]
enum ConfigureOption {
    EveBoxChannel,
    Shortcuts,
}

const CONFIGURE_OPTIONS: [ConfigureOption; 2] =
    [ConfigureOption::EveBoxChannel, ConfigureOption::Shortcuts];

impl crate::menu::configure::Backend for WindowsPlatform<'_> {
    fn platform(&mut self, _config: &Config) -> &dyn Platform {
        self
    }

    fn platform_options(&self, config: &Config) -> Vec<String> {
        CONFIGURE_OPTIONS
            .iter()
            .map(|option| match option {
                ConfigureOption::EveBoxChannel => {
                    format!("EveBox Release Channel [{}]", config.windows.evebox_channel)
                }
                ConfigureOption::Shortcuts => "Add Desktop Shortcuts".to_string(),
            })
            .collect()
    }

    fn run_platform_option(&mut self, config: &mut Config, index: usize) -> Result<()> {
        match CONFIGURE_OPTIONS[index] {
            ConfigureOption::EveBoxChannel => {
                if let Some(channel) = prompt_for_evebox_channel(config.windows.evebox_channel) {
                    config.windows.evebox_channel = channel;
                }
            }
            ConfigureOption::Shortcuts => crate::prompt::report_and_pause(
                "Failed to add desktop shortcuts",
                add_shortcuts(config),
            ),
        }
        Ok(())
    }
}

impl crate::menu::wizard::Backend for WindowsPlatform<'_> {
    fn platform(&mut self, _config: &Config) -> &dyn Platform {
        self
    }

    fn platform_questions(&mut self, config: &mut Config) -> Result<bool> {
        let Some(channel) = prompt_for_evebox_channel(config.windows.evebox_channel) else {
            return Ok(false);
        };
        config.windows.evebox_channel = channel;
        Ok(true)
    }

    fn install(&mut self, config: &Config) -> Result<()> {
        install_configured_components(self.paths, config)
    }

    fn update_rules(&mut self, _config: &Config) -> Result<()> {
        update_rules(self.paths, false, false)
    }
}

impl crate::menu::main::Backend for WindowsPlatform<'_> {
    fn status(&mut self, config: &Config) -> Status {
        let status = match windows_status(self.paths, config) {
            Ok(status) => status,
            Err(err) => {
                error!("Failed to determine Windows service status: {}", err);
                WindowsStatus::default()
            }
        };
        log_status(status, config);
        let restart_recommended = crate::restart_notice::pending(self.paths.root());
        Status {
            running: status.any_running(),
            ready_to_start: status.ready_to_start(),
            restart_recommended,
        }
    }

    /// The release channel is applied by Update, not by a restart.
    fn acknowledge_saved_changes(&mut self, original: &mut Config, current: &Config) {
        if current.windows.evebox_channel != original.windows.evebox_channel {
            info!(
                "EveBox channel saved as {}. Choose Update to apply it; a restart alone does not change the installed build.",
                current.windows.evebox_channel
            );
            original.windows.evebox_channel = current.windows.evebox_channel;
        }
    }

    fn start(&mut self, _config: &Config) -> Result<()> {
        start_stack(self.paths, false, None)
    }

    fn stop(&mut self, _config: &Config) -> Result<()> {
        stop_stack(self.paths)
    }

    fn restart(&mut self, _config: &Config) -> Result<()> {
        restart_stack(self.paths)
    }

    fn install(&mut self, config: &mut Config) -> Result<()> {
        install_with(self.paths, config)
    }

    fn update(&mut self, _config: &Config) -> Result<UpdateOutcome> {
        Ok(match upgrade_windows_components(self.paths)? {
            super::update::UpdateOutcome::Completed => UpdateOutcome::Completed,
            super::update::UpdateOutcome::RestartEveCtl => UpdateOutcome::ExitMenu,
        })
    }

    fn other(&mut self, config: &mut Config) -> Result<()> {
        other_menu(self.paths, config)
    }
}
