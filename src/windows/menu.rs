// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Interactive menus and the status display.

use super::evebox::{
    evebox_installed_channel, find_evebox_exe, get_evebox_installed_version,
    reset_evebox_admin_password,
};
use super::install::{
    add_shortcuts, install_configured_components, install_with, upgrade_windows_components,
};
use super::interfaces::{
    get_configured_interface_guid, get_configured_interface_value, get_windows_interfaces,
    list_interfaces,
};
use super::paths::{
    ensure_dir, get_evebox_data_dir, get_evebox_install_dir, get_evebox_pid_path,
    get_evebox_root_dir, get_evebox_runtime_path, get_evectl_config_path, get_evectl_data_dir,
    get_suricata_filestore_dir, get_suricata_pcap_dir, load_evectl_config,
};
use super::rules::{WindowsRulesBackend, update_rules};
use super::runtime::{
    ROLE_EVEBOX, ROLE_EVEBOX_AGENT, ROLE_HOUSEKEEPER, ROLE_SURICATA, count_named_processes,
    managed_process_is_running,
};
use super::stack::{evebox_server_url, restart_stack, start_stack, stop_stack};
use super::suricata::find_suricata_executable;
use super::uninstall::uninstall_windows_components;
use super::update::UpdateOutcome;
use crate::config::EveBoxChannel;
use crate::prelude::*;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
enum OtherMenuOption {
    Install,
    Uninstall,
    Interfaces,
    Info,
    Return,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct WindowsStatus {
    suricata_enabled: bool,
    suricata_installed: bool,
    suricata_running: bool,
    evebox_installed: bool,
    evebox_server_enabled: bool,
    evebox_server_running: bool,
    evebox_agent_enabled: bool,
    evebox_agent_running: bool,
    housekeeper_enabled: bool,
    housekeeper_running: bool,
}

impl WindowsStatus {
    fn any_enabled(self) -> bool {
        self.suricata_enabled || self.evebox_server_enabled || self.evebox_agent_enabled
    }

    fn any_running(self) -> bool {
        self.suricata_running
            || self.evebox_server_running
            || self.evebox_agent_running
            || self.housekeeper_running
    }

    fn evebox_enabled(self) -> bool {
        self.evebox_server_enabled || self.evebox_agent_enabled
    }

    /// True when every enabled service has an executable the menu's
    /// Start action can launch.
    fn ready_to_start(self) -> bool {
        self.any_enabled()
            && (!self.suricata_enabled || self.suricata_installed)
            && (!self.evebox_enabled() || self.evebox_installed)
    }
}

pub(super) fn windows_status(config: &crate::config::Config) -> Result<WindowsStatus> {
    Ok(WindowsStatus {
        suricata_enabled: config.suricata.enabled,
        suricata_installed: find_suricata_executable().is_some(),
        suricata_running: managed_process_is_running(ROLE_SURICATA)?,
        evebox_installed: find_evebox_exe(&get_evebox_install_dir()?)?.is_some(),
        evebox_server_enabled: config.evebox_server.enabled,
        evebox_server_running: managed_process_is_running(ROLE_EVEBOX)?,
        evebox_agent_enabled: config.evebox_agent.enabled,
        evebox_agent_running: managed_process_is_running(ROLE_EVEBOX_AGENT)?,
        housekeeper_enabled: super::file_extraction::cleanup_enabled(config),
        housekeeper_running: managed_process_is_running(ROLE_HOUSEKEEPER)?,
    })
}

pub(super) fn log_status(status: WindowsStatus, config: &crate::config::Config) {
    if status.housekeeper_running {
        info!("{:-13}: running", "Housekeeper");
    } else if status.housekeeper_enabled {
        warn!("{:-13}: not running", "Housekeeper");
    }
    if status.suricata_enabled {
        if status.suricata_running {
            info!("{:-13}: running", "Suricata");
        } else if status.suricata_installed {
            warn!("{:-13}: not running", "Suricata");
        } else {
            warn!("{:-13}: not installed", "Suricata");
        }
    } else {
        debug!("{:-13}: not enabled", "Suricata");
    }

    if status.evebox_server_enabled {
        if status.evebox_server_running {
            info!(
                "{:-13}: running {}",
                "EveBox Server",
                evebox_server_url(config)
            );
        } else if status.evebox_installed {
            warn!("{:-13}: not running", "EveBox Server");
        } else {
            warn!("{:-13}: not installed", "EveBox Server");
        }
    } else {
        debug!("{:-13}: not enabled", "EveBox Server");
    }

    if status.evebox_agent_enabled {
        if status.evebox_agent_running {
            info!("{:-13}: running", "EveBox Agent");
        } else if status.evebox_installed {
            warn!("{:-13}: not running", "EveBox Agent");
        } else {
            warn!("{:-13}: not installed", "EveBox Agent");
        }
    } else {
        debug!("{:-13}: not enabled", "EveBox Agent");
    }

    if !status.any_enabled() {
        info!("No services enabled");
    }
}

pub(super) fn menu_main() -> Result<()> {
    // Like the Linux menu, the configuration is held in memory,
    // mutated by the configure menus, and only saved here.
    let mut config = match load_evectl_config() {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            crate::config::Config::default_with_filename(&get_evectl_config_path()?)
        }
    };

    offer_install_if_missing(&mut config);

    crate::menu::main::menu(&mut config, &mut WindowsMainMenuBackend)
}

struct WindowsMainMenuBackend;

impl crate::menu::main::Backend for WindowsMainMenuBackend {
    fn status(&mut self, config: &crate::config::Config) -> crate::menu::main::Status {
        let status = match windows_status(config) {
            Ok(status) => status,
            Err(err) => {
                error!("Failed to determine Windows service status: {}", err);
                WindowsStatus::default()
            }
        };
        log_status(status, config);
        let restart_recommended = get_evectl_data_dir()
            .map(|data_dir| super::update::restart_recommended(&data_dir))
            .unwrap_or(false);
        crate::menu::main::Status {
            running: status.any_running(),
            ready_to_start: status.ready_to_start(),
            restart_recommended,
        }
    }

    fn save_config(&mut self, config: &crate::config::Config) -> Result<()> {
        ensure_dir(&get_evectl_data_dir()?)?;
        config.save()
    }

    /// The release channel is applied by Update, not by a restart.
    fn acknowledge_saved_changes(
        &mut self,
        original: &mut crate::config::Config,
        current: &crate::config::Config,
    ) {
        if current.windows.evebox_channel != original.windows.evebox_channel {
            info!(
                "EveBox channel saved as {}. Choose Update to apply it; a restart alone does not change the installed build.",
                current.windows.evebox_channel
            );
            original.windows.evebox_channel = current.windows.evebox_channel;
        }
    }

    fn start(&mut self, _config: &crate::config::Config) -> Result<()> {
        start_stack(false, None)
    }

    fn stop(&mut self, _config: &crate::config::Config) -> Result<()> {
        stop_stack()
    }

    fn restart(&mut self, _config: &crate::config::Config) -> Result<()> {
        restart_stack()
    }

    fn install(&mut self, config: &mut crate::config::Config) -> Result<()> {
        install_with(config)
    }

    fn update_rules(&mut self, _config: &crate::config::Config) -> Result<()> {
        update_rules(false, false)
    }

    fn rules(&mut self, _config: &crate::config::Config) -> Box<dyn crate::rules::Backend + '_> {
        Box::new(WindowsRulesBackend)
    }

    fn update(
        &mut self,
        _config: &crate::config::Config,
    ) -> Result<crate::menu::main::UpdateOutcome> {
        Ok(match upgrade_windows_components()? {
            UpdateOutcome::Completed => crate::menu::main::UpdateOutcome::Completed,
            UpdateOutcome::RestartEveCtl => crate::menu::main::UpdateOutcome::ExitMenu,
        })
    }

    fn configure(&mut self, config: &mut crate::config::Config) -> Result<()> {
        crate::menu::configure::menu(config, &mut WindowsConfigureBackend)
    }

    fn other(&mut self, config: &mut crate::config::Config) -> Result<()> {
        other_menu(config)
    }
}

/// Mirror the Linux onboarding: on first run walk through the setup
/// wizard; afterwards, offer to install any missing components.
fn offer_install_if_missing(config: &mut crate::config::Config) {
    let status = match windows_status(config) {
        Ok(status) => status,
        Err(_) => return,
    };

    if !status.any_enabled() {
        if let Err(err) = wizard(config)
            && !prompt_was_cancelled(&err)
        {
            error!("{}", err);
            crate::prompt::enter();
        }
        return;
    }

    if status.ready_to_start() {
        return;
    }

    if status.suricata_enabled && !status.suricata_installed {
        info!("Suricata is not installed");
    }
    if status.evebox_enabled() && !status.evebox_installed {
        info!("EveBox is not installed");
    }

    if let Ok(true) = inquire::Confirm::new("Required components not installed, install now?")
        .with_default(true)
        .prompt()
        && let Err(err) = install_configured_components(config)
    {
        error!("Failed to install components: {}", err);
        crate::prompt::enter();
    }
}

pub(super) fn wizard(config: &mut crate::config::Config) -> Result<()> {
    crate::menu::wizard::menu(config, &mut WindowsWizardBackend)
}

struct WindowsWizardBackend;

impl crate::menu::wizard::Backend for WindowsWizardBackend {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_> {
        Box::new(WindowsSuricataBackend)
    }

    fn evebox_server(&self) -> Box<dyn crate::evebox::configuration::Backend + '_> {
        Box::new(WindowsEveBoxServerBackend)
    }

    fn platform_questions(&mut self, config: &mut crate::config::Config) -> Result<bool> {
        let Some(channel) = prompt_for_evebox_channel(config.windows.evebox_channel) else {
            return Ok(false);
        };
        config.windows.evebox_channel = channel;
        Ok(true)
    }

    fn install(&mut self, config: &crate::config::Config) -> Result<()> {
        install_configured_components(config)
    }

    fn update_rules(&mut self, _config: &crate::config::Config) -> Result<()> {
        update_rules(false, false)
    }

    fn save_config(&mut self, config: &crate::config::Config) -> Result<()> {
        ensure_dir(&get_evectl_data_dir()?)?;
        config.save()
    }
}

fn prompt_for_evebox_channel(current: EveBoxChannel) -> Option<EveBoxChannel> {
    let mut selections = crate::prompt::Selections::new();
    selections.push(
        EveBoxChannel::Development,
        "Development: latest main-branch build",
    );
    selections.push(EveBoxChannel::Release, "Release: latest stable release");
    inquire::Select::new(
        "EveBox release channel (server and agent)",
        selections.to_vec(),
    )
    .with_starting_cursor(match current {
        EveBoxChannel::Development => 0,
        EveBoxChannel::Release => 1,
    })
    .with_help_message(
        "Apply with Update. Back up data before switching from development to release.",
    )
    .prompt()
    .ok()
    .map(|selection| selection.tag)
}

pub(super) fn config_set_evebox_channel(channel: Option<EveBoxChannel>) -> Result<()> {
    let mut config = load_evectl_config()?;
    let Some(channel) =
        channel.or_else(|| prompt_for_evebox_channel(config.windows.evebox_channel))
    else {
        return Ok(());
    };
    config.windows.evebox_channel = channel;
    ensure_dir(&get_evectl_data_dir()?)?;
    config.save()?;
    println!(
        "EveBox channel saved as {channel}. Run 'evectl update' to apply it to an existing installation."
    );
    Ok(())
}

struct WindowsConfigureBackend;

const CONFIGURE_EVEBOX_CHANNEL: &str = "evebox-channel";
const CONFIGURE_SHORTCUTS: &str = "shortcuts";

impl crate::menu::configure::Backend for WindowsConfigureBackend {
    fn suricata(&self) -> Box<dyn crate::suricata::configuration::Backend + '_> {
        Box::new(WindowsSuricataBackend)
    }

    fn fpc(&self) -> Box<dyn crate::fpc::Backend + '_> {
        Box::new(WindowsFpcBackend)
    }

    fn configure_evebox_server(&mut self, config: &mut crate::config::Config) -> Result<()> {
        crate::menu::evebox_server::menu(config, &WindowsEveBoxServerBackend)
    }

    fn platform_options(
        &self,
        config: &crate::config::Config,
    ) -> Vec<crate::menu::configure::PlatformOption> {
        vec![
            crate::menu::configure::PlatformOption {
                id: CONFIGURE_EVEBOX_CHANNEL,
                label: format!("EveBox Release Channel [{}]", config.windows.evebox_channel),
            },
            crate::menu::configure::PlatformOption {
                id: CONFIGURE_SHORTCUTS,
                label: "Add Desktop Shortcuts".to_string(),
            },
        ]
    }

    fn run_platform_option(&mut self, config: &mut crate::config::Config, id: &str) -> Result<()> {
        match id {
            CONFIGURE_EVEBOX_CHANNEL => {
                if let Some(channel) = prompt_for_evebox_channel(config.windows.evebox_channel) {
                    config.windows.evebox_channel = channel;
                }
            }
            CONFIGURE_SHORTCUTS => {
                run_menu_action_with_pause("Failed to add desktop shortcuts", add_shortcuts)
            }
            _ => bail!("Unknown configuration option: {id}"),
        }
        Ok(())
    }
}

struct WindowsFpcBackend;

impl crate::fpc::Backend for WindowsFpcBackend {
    fn spool_dir(&self) -> Result<PathBuf> {
        get_suricata_pcap_dir()
    }

    fn check_remove_spool(&self) -> Result<()> {
        if count_named_processes("suricata")? > 0 {
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

struct WindowsSuricataBackend;

impl crate::suricata::configuration::Backend for WindowsSuricataBackend {
    fn interfaces(&self) -> Result<Vec<crate::suricata::configuration::Interface>> {
        Ok(get_windows_interfaces()?
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
        get_suricata_filestore_dir()
    }

    fn check_remove_extracted_files(&self) -> Result<()> {
        if count_named_processes("suricata")? > 0 || managed_process_is_running(ROLE_HOUSEKEEPER)? {
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

struct WindowsEveBoxServerBackend;

impl crate::evebox::configuration::Backend for WindowsEveBoxServerBackend {
    fn supports_search_engines(&self) -> bool {
        false
    }

    fn bind_addresses(&self) -> Result<Vec<crate::evebox::configuration::BindAddress>> {
        Ok(get_windows_interfaces()?
            .into_iter()
            .filter(|interface| interface.ip_address.parse::<std::net::Ipv4Addr>().is_ok())
            .map(|interface| crate::evebox::configuration::BindAddress {
                interface: interface.name,
                address: interface.ip_address,
            })
            .collect())
    }

    fn reset_password(&self) -> Result<()> {
        reset_evebox_admin_password()
    }
}

fn other_menu(config: &mut crate::config::Config) -> Result<()> {
    loop {
        crate::term::title("EveCtl: Other Menu Items");

        let mut selections = crate::prompt::Selections::with_index();
        selections.push(OtherMenuOption::Install, "Install Components");
        selections.push(OtherMenuOption::Uninstall, "Uninstall Components");
        selections.push(OtherMenuOption::Interfaces, "List Network Interfaces");
        selections.push(OtherMenuOption::Info, "Show Paths and Installation Info");
        selections.push(OtherMenuOption::Return, "Return");

        let selection =
            match inquire::Select::new("Select menu option", selections.to_vec()).prompt() {
                Ok(selection) => selection,
                Err(_) => break,
            };

        match selection.tag {
            OtherMenuOption::Install => {
                run_menu_action_with_pause("Installation failed", || install_with(config))
            }
            OtherMenuOption::Uninstall => {
                let uninstall =
                    inquire::Confirm::new("Uninstall EveBox, Suricata, and evectl-managed Npcap?")
                        .with_default(false)
                        .prompt()
                        .unwrap_or(false);
                if uninstall {
                    run_menu_action_with_pause(
                        "Uninstallation failed",
                        uninstall_windows_components,
                    );
                }
            }
            OtherMenuOption::Interfaces => {
                run_menu_action_with_pause("Failed to list network interfaces", list_interfaces)
            }
            OtherMenuOption::Info => {
                run_menu_action_with_pause("Failed to show project information", project_info)
            }
            OtherMenuOption::Return => break,
        }
    }

    Ok(())
}

fn run_menu_action_with_pause(message: &str, action: impl FnOnce() -> Result<()>) {
    if let Err(err) = action() {
        error!("{}: {}", message, err);
    }
    crate::prompt::enter();
}

/// True when a prompt error is the user backing out (ESC or Ctrl-C)
/// rather than a real failure.
fn prompt_was_cancelled(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<inquire::InquireError>(),
        Some(
            inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted
        )
    )
}

pub(super) fn project_info() -> Result<()> {
    let data_root = get_evectl_data_dir()?;

    let evectl_config = data_root.join("evectl.toml");
    let suricata_config_dir = data_root.join("suricata");
    let suricata_rules_dir = suricata_config_dir.join("lib").join("rules");
    let suricata_update_dir = suricata_config_dir.join("lib").join("update");
    let suricata_update_cache_dir = suricata_update_dir.join("cache");
    let suricata_install_dir = data_root.join("suricata").join("install");
    let suricata_log_dir = data_root.join("suricata").join("log");
    let suricata_run_dir = data_root.join("suricata").join("run");
    let evebox_root_dir = get_evebox_root_dir()?;
    let evebox_install_dir = get_evebox_install_dir()?;
    let evebox_data_dir = get_evebox_data_dir()?;
    let evebox_exe = find_evebox_exe(&evebox_install_dir)?;
    let evectl_exe = std::env::current_exe().ok();

    println!("Windows path-based directories:");
    println!("  Data root:                 {}", data_root.display());
    if let Some(evectl_exe) = &evectl_exe {
        println!("  Current EveCtl binary:     {}", evectl_exe.display());
    } else {
        println!("  Current EveCtl binary:     <unknown>");
    }
    println!();

    println!("Config and rules paths in use:");
    println!("  EveCtl config file:        {}", evectl_config.display());
    match get_configured_interface_value() {
        Ok(Some(interface)) => println!("  Configured interface:      {}", interface),
        Ok(None) => println!("  Configured interface:      <not set>"),
        Err(err) => println!("  Configured interface:      <error: {}>", err),
    }
    match get_configured_interface_guid() {
        Ok(Some(guid)) => println!("  Resolved interface GUID:   {}", guid),
        Ok(None) => println!("  Resolved interface GUID:   <not set>"),
        Err(err) => println!("  Resolved interface GUID:   <error: {}>", err),
    }
    println!(
        "  Suricata config directory: {}",
        suricata_config_dir.display()
    );
    println!(
        "  Suricata rules directory:  {}",
        suricata_rules_dir.display()
    );
    println!(
        "  Rule update state:         {}",
        suricata_update_dir.display()
    );
    println!(
        "  Rule update cache:         {}",
        suricata_update_cache_dir.display()
    );
    println!();

    println!("Suricata paths in use:");
    println!(
        "  Suricata install dir:      {}",
        suricata_install_dir.display()
    );
    println!(
        "  Suricata logs:             {}",
        suricata_log_dir.display()
    );
    println!(
        "  Suricata packet captures:  {}",
        get_suricata_pcap_dir()?.display()
    );
    println!(
        "  Suricata runtime files:    {}",
        suricata_run_dir.display()
    );
    println!();

    println!("Other Windows data paths:");
    println!("  EveBox root directory:     {}", evebox_root_dir.display());
    println!(
        "  EveBox install directory:  {}",
        evebox_install_dir.display()
    );
    println!("  EveBox data directory:     {}", evebox_data_dir.display());
    println!(
        "  Selected EveBox channel:   {}",
        load_evectl_config()?.windows.evebox_channel
    );
    println!(
        "  EveBox PID file:           {}",
        get_evebox_pid_path()?.display()
    );
    println!(
        "  EveBox runtime metadata:   {}",
        get_evebox_runtime_path()?.display()
    );
    if let Some(evebox_exe) = evebox_exe {
        println!("  Current EveBox binary:     {}", evebox_exe.display());
        if let Some(version) = get_evebox_installed_version()? {
            println!("  Current EveBox version:    {}", version);
        }
        if let Some(channel) = evebox_installed_channel(&evebox_install_dir)? {
            println!("  Installed EveBox channel:  {}", channel);
        }
    } else {
        println!(
            "  Current EveBox binary:     {} (not installed)",
            evebox_install_dir.join("evebox.exe").display()
        );
    }

    Ok(())
}
