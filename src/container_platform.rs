// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! The Linux platform behind the shared menus, where every service
//! runs in a container managed by Docker or Podman.

use std::path::PathBuf;

use crate::config::EveOutput;
use crate::container::{CommandExt, Container, RunCommandBuilder};
use crate::evebox::configuration::BindAddress;
use crate::menu::main::{Status, UpdateOutcome};
use crate::platform::Platform;
use crate::prelude::*;
use crate::rules::{OverrideFile, Ruleset};
use crate::suricata::configuration::Interface;
use crate::update::UpdateContinuationArgs;
use crate::{menu, rules, services, suricata, systemd};

/// The menus edit a configuration of their own; the runtime snapshot
/// here is brought up to date with it before each action, and copied
/// back after actions that edit it through the runtime.
pub(crate) struct ContainerBackend<'a> {
    runtime: Context,
    /// Only the main menu runs updates.
    update_continuation_args: Option<&'a UpdateContinuationArgs>,
}

impl<'a> ContainerBackend<'a> {
    pub(crate) fn new(context: &Context) -> Self {
        Self {
            runtime: context.clone(),
            update_continuation_args: None,
        }
    }

    fn with_update_args(context: &Context, args: &'a UpdateContinuationArgs) -> Self {
        Self {
            runtime: context.clone(),
            update_continuation_args: Some(args),
        }
    }

    fn sync(&mut self, config: &Config) -> &Context {
        if self.runtime.config != *config {
            self.runtime.config = config.clone();
        }
        &self.runtime
    }

    /// Run an action that edits the configuration through the runtime.
    fn edit(
        &mut self,
        config: &mut Config,
        action: impl FnOnce(&mut Context) -> Result<()>,
    ) -> Result<()> {
        self.sync(config);
        let result = action(&mut self.runtime);
        *config = self.runtime.config.clone();
        result
    }

    /// Whether a named container is running. Confirm absence by
    /// listing; an inspect failure may mean the daemon is unavailable,
    /// not that the container has stopped.
    fn is_active(&self, existing: &[String], name: &str) -> Result<bool> {
        if !existing.contains(&name.to_string()) {
            return Ok(false);
        }
        let state = self.runtime.manager.state(name)?;
        Ok(state.running || state.restarting)
    }

    fn remove_directory(&self, directory: PathBuf) -> Result<()> {
        if directory.exists() {
            crate::uninstall::remove_directory(&self.runtime, &directory)?;
        }
        Ok(())
    }
}

pub(crate) fn menu_main(
    mut context: Context,
    update_continuation_args: &UpdateContinuationArgs,
) -> Result<()> {
    let mut backend = ContainerBackend::with_update_args(&context, update_continuation_args);
    menu::main::menu(&mut context.config, &mut backend)
}

pub(crate) fn wizard(context: &mut Context) -> Result<()> {
    let mut backend = ContainerBackend::new(context);
    menu::wizard::menu(&mut context.config, &mut backend)
}

pub(crate) fn configure_menu(context: &mut Context) -> Result<()> {
    let mut backend = ContainerBackend::new(context);
    menu::configure::menu(&mut context.config, &mut backend)
}

/// Hidden CLI entry point; settings are edited directly in the
/// caller's configuration.
pub(crate) fn suricata_menu(context: &mut Context) -> Result<()> {
    let backend = ContainerBackend::new(context);
    menu::suricata::menu(&mut context.config, &backend)
}

/// Hidden CLI entry point; the configuration is saved on exit as no
/// caller persists it.
pub(crate) fn evebox_server_menu(context: &mut Context) -> Result<()> {
    let backend = ContainerBackend::new(context);
    menu::evebox_server::menu(&mut context.config, &backend)?;
    if context.config != backend.runtime.config {
        context.config.save()?;
    }
    Ok(())
}

impl crate::suricata::configuration::Backend for ContainerBackend<'_> {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        Ok(crate::system::get_interfaces()?
            .into_iter()
            .map(|interface| Interface {
                name: interface.name,
                address: interface.addr4.into_iter().next(),
            })
            .collect())
    }

    fn eve_outputs(&self) -> &'static [EveOutput] {
        &[EveOutput::UnixStream, EveOutput::File]
    }

    fn filestore_dir(&self) -> Result<PathBuf> {
        Ok(suricata::filestore_dir(&self.runtime))
    }

    fn check_remove_extracted_files(&self) -> Result<()> {
        // Never treat a failed inspection as permission to delete files.
        let existing = self.runtime.manager.container_names()?;
        for name in [
            suricata::container_name(&self.runtime),
            crate::housekeeper::container_name(&self.runtime),
            crate::housekeeper::legacy_container_name(&self.runtime),
        ] {
            if self.is_active(&existing, &name)? {
                bail!(
                    "Suricata or housekeeping is running; stop services before removing extracted files"
                );
            }
        }
        Ok(())
    }

    fn remove_extracted_files(&self) -> Result<()> {
        self.check_remove_extracted_files()?;
        self.remove_directory(self.filestore_dir()?)
    }
}

impl crate::fpc::Backend for ContainerBackend<'_> {
    fn spool_dir(&self) -> Result<PathBuf> {
        Ok(suricata::pcap_dir(&self.runtime))
    }

    fn check_remove_spool(&self) -> Result<()> {
        let existing = self.runtime.manager.container_names()?;
        if self.is_active(&existing, &suricata::container_name(&self.runtime))? {
            bail!("Suricata is running; stop services before removing packet captures");
        }
        Ok(())
    }

    fn remove_spool(&self) -> Result<()> {
        self.check_remove_spool()?;
        self.remove_directory(self.spool_dir()?)
    }
}

impl crate::evebox::configuration::Backend for ContainerBackend<'_> {
    fn supports_search_engines(&self) -> bool {
        true
    }

    fn bind_addresses(&self) -> Result<Vec<BindAddress>> {
        Ok(crate::system::get_interfaces()?
            .into_iter()
            .flat_map(|interface| {
                interface.addr4.into_iter().map(move |address| BindAddress {
                    interface: interface.name.clone(),
                    address,
                })
            })
            .collect())
    }

    fn reset_password(&self) -> Result<()> {
        crate::evebox::server::reset_password(&self.runtime)
    }
}

impl rules::Backend for ContainerBackend<'_> {
    fn available_rulesets(&self) -> Result<Vec<Ruleset>> {
        Ok(rules::load_rule_index(&self.runtime)?
            .sources
            .into_iter()
            .map(|(id, source)| Ruleset {
                id,
                summary: Some(source.summary),
                can_enable: source.obsolete.is_none() && source.parameters.is_none(),
            })
            .collect())
    }

    fn enabled_rulesets(&self) -> Result<Vec<Ruleset>> {
        let enabled = rules::get_enabled_ruleset(&self.runtime)?;
        if enabled.is_empty() {
            return Ok(vec![]);
        }
        let index = rules::load_rule_index(&self.runtime).ok();
        Ok(enabled
            .into_iter()
            .map(|id| {
                let summary = index
                    .as_ref()
                    .and_then(|index| index.sources.get(&id))
                    .map(|source| source.summary.clone());
                Ruleset {
                    id,
                    summary,
                    can_enable: false,
                }
            })
            .collect())
    }

    fn enable_ruleset(&self, id: &str) -> Result<()> {
        rules::enable_ruleset(&self.runtime, id)
    }

    fn disable_ruleset(&self, id: &str) -> Result<()> {
        rules::disable_ruleset(&self.runtime, id)
    }

    fn update_sources(&self) -> Result<()> {
        rules::update_sources(&self.runtime)
    }

    fn update_rules(&self) -> Result<()> {
        rules::update_rules(&self.runtime, &[])
    }

    fn override_path(&self, file: OverrideFile) -> Option<PathBuf> {
        Some(self.runtime.config_dir().join(file.filename()))
    }

    fn write_override_template(&self, file: OverrideFile) -> Result<()> {
        let source = format!(
            "/usr/lib/suricata/python/suricata/update/configs/{}",
            file.filename()
        );
        let output = RunCommandBuilder::new(
            self.runtime.manager,
            self.runtime.image_name(Container::Suricata),
        )
        .rm()
        .args(&["cat", &source])
        .build()
        .status_output()?;
        std::fs::create_dir_all(self.runtime.config_dir())?;
        std::fs::write(self.runtime.config_dir().join(file.filename()), output)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum ConfigureOption {
    ContainerImages,
    StartOnBoot,
}

const CONFIGURE_OPTIONS: [ConfigureOption; 2] = [
    ConfigureOption::ContainerImages,
    ConfigureOption::StartOnBoot,
];

impl menu::configure::Backend for ContainerBackend<'_> {
    fn platform(&mut self, config: &Config) -> &dyn Platform {
        self.sync(config);
        self
    }

    fn platform_options(&self, _config: &Config) -> Vec<String> {
        CONFIGURE_OPTIONS
            .iter()
            .map(|option| match option {
                ConfigureOption::ContainerImages => "Containers Images".to_string(),
                ConfigureOption::StartOnBoot => {
                    if systemd::is_enabled() {
                        "Disable Start on Boot".to_string()
                    } else {
                        "Enable Start on Boot".to_string()
                    }
                }
            })
            .collect()
    }

    fn run_platform_option(&mut self, config: &mut Config, index: usize) -> Result<()> {
        match CONFIGURE_OPTIONS[index] {
            ConfigureOption::ContainerImages => self.edit(config, |context| {
                menu::containers::edit(context);
                Ok(())
            }),
            ConfigureOption::StartOnBoot => start_on_boot(&self.runtime),
        }
    }
}

fn start_on_boot(context: &Context) -> Result<()> {
    if !systemd::is_enabled() {
        info!("Start on boot is enabled by using sudo to install a systemd service file.");
        if !crate::prompt::confirm("Do you wish to continue?") {
            return Ok(());
        }
        systemd::install(&context.root, context.manager)?;
    } else if crate::prompt::confirm("Do you wish to disable start on boot?")
        && let Err(err) = systemd::remove()
    {
        error!("Failed to remove systemd unit: {}", err);
    }
    Ok(())
}

impl menu::wizard::Backend for ContainerBackend<'_> {
    fn platform(&mut self, config: &Config) -> &dyn Platform {
        self.sync(config);
        self
    }

    fn install(&mut self, config: &Config) -> Result<()> {
        let context = self.sync(config);
        if config.suricata.enabled {
            info!("Pulling Suricata image...");
            context
                .manager
                .pull(&context.image_name(Container::Suricata))?;
        }

        info!("Pulling EveBox image...");
        context
            .manager
            .pull(&context.image_name(Container::EveBox))?;

        if config.elasticsearch_enabled() {
            info!("Pulling {} image...", config.elasticsearch.engine.name());
            context
                .manager
                .pull(crate::elastic::docker_image(context))?;
        }
        Ok(())
    }

    fn update_rules(&mut self, config: &Config) -> Result<()> {
        let context = self.sync(config);
        suricata::mkdirs(context)?;
        rules::update_rules(context, &["--no-reload", "--no-test"])
    }
}

impl menu::main::Backend for ContainerBackend<'_> {
    fn status(&mut self, config: &Config) -> Status {
        let context = self.sync(config);
        crate::status::log_status(context);
        let running = services::enabled_containers(context)
            .iter()
            .any(|(_, name)| context.manager.is_running(name));
        Status {
            running,
            // Containers are pulled on start, so there is nothing to
            // install and `install` is never offered.
            ready_to_start: true,
            restart_recommended: crate::restart_notice::pending(&context.root),
        }
    }

    fn start(&mut self, config: &Config) -> Result<()> {
        if services::start(self.sync(config)) {
            Ok(())
        } else {
            bail!("One or more services failed to start")
        }
    }

    fn stop(&mut self, config: &Config) -> Result<()> {
        if services::stop_all(self.sync(config)) {
            Ok(())
        } else {
            bail!("One or more services failed to stop")
        }
    }

    fn restart(&mut self, config: &Config) -> Result<()> {
        services::restart(self.sync(config))
    }

    fn install(&mut self, _config: &mut Config) -> Result<()> {
        bail!("Containers are installed on start")
    }

    fn update(&mut self, config: &Config) -> Result<UpdateOutcome> {
        let args = self
            .update_continuation_args
            .context("Updates are only run from the main menu")?;
        // A self-update replaces the process and never returns.
        if !crate::update::update(self.sync(config), args, false, true, false) {
            bail!("Update or service restart failed");
        }
        Ok(UpdateOutcome::Completed)
    }

    fn other(&mut self, config: &mut Config) -> Result<()> {
        menu::other::menu(self.sync(config));
        Ok(())
    }
}
