// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Interactive menus and the status display.

use super::evebox::{evebox_installed_channel, evebox_installed_version, find_evebox_exe};
use super::install::{install_configured_components, install_with};
use super::interfaces::{configured_interface_guid, configured_interface_value, list_interfaces};
use super::paths::{Paths, load_evectl_config};
use super::platform::WindowsPlatform;
use super::runtime::Role;
use super::stack::{WindowsStatus, evebox_server_url, windows_status};
use super::uninstall::uninstall_windows_components;
use crate::config::EveBoxChannel;
use crate::prelude::*;

#[derive(Debug, Clone, Copy)]
enum OtherMenuOption {
    Install,
    Uninstall,
    Interfaces,
    Info,
    Return,
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

pub(super) fn menu_main(paths: &Paths) -> Result<()> {
    // Like the Linux menu, the configuration is held in memory,
    // mutated by the configure menus, and only saved here.
    let mut config = match load_evectl_config(paths) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load configuration: {}", err);
            crate::config::Config::default_with_filename(&paths.config_file())
        }
    };

    offer_install_if_missing(paths, &mut config);

    crate::menu::main::menu(&mut config, &mut WindowsPlatform { paths })
}

/// Mirror the Linux onboarding: on first run walk through the setup
/// wizard; afterwards, offer to install any missing components.
fn offer_install_if_missing(paths: &Paths, config: &mut crate::config::Config) {
    let status = match windows_status(paths, config) {
        Ok(status) => status,
        Err(_) => return,
    };

    if !status.any_enabled() {
        crate::prompt::report("Setup wizard failed", wizard(paths, config));
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

    if crate::prompt::confirm("Required components not installed, install now?") {
        crate::prompt::report(
            "Failed to install components",
            install_configured_components(paths, config),
        );
    }
}

pub(super) fn wizard(paths: &Paths, config: &mut crate::config::Config) -> Result<()> {
    crate::menu::wizard::menu(config, &mut WindowsPlatform { paths })
}

pub(super) fn prompt_for_evebox_channel(current: EveBoxChannel) -> Option<EveBoxChannel> {
    let mut selections = crate::prompt::Selections::new();
    selections.push(
        EveBoxChannel::Development,
        "Development: latest main-branch build",
    );
    selections.push(EveBoxChannel::Release, "Release: latest stable release");
    selections
        .prompt_with("EveBox release channel (server and agent)", |select| {
            select
                .with_starting_cursor(match current {
                    EveBoxChannel::Development => 0,
                    EveBoxChannel::Release => 1,
                })
                .with_help_message(
                    "Apply with Update. Back up data before switching from development to release.",
                )
        })
        .ok()
        .flatten()
}

pub(super) fn config_set_evebox_channel(
    paths: &Paths,
    channel: Option<EveBoxChannel>,
) -> Result<()> {
    let mut config = load_evectl_config(paths)?;
    let Some(channel) =
        channel.or_else(|| prompt_for_evebox_channel(config.windows.evebox_channel))
    else {
        return Ok(());
    };
    config.windows.evebox_channel = channel;
    config.save()?;
    println!(
        "EveBox channel saved as {channel}. Run 'evectl update' to apply it to an existing installation."
    );
    Ok(())
}

pub(super) fn other_menu(paths: &Paths, config: &mut crate::config::Config) -> Result<()> {
    loop {
        crate::term::title("EveCtl: Other Menu Items");

        let mut selections = crate::prompt::Selections::with_index();
        selections.push(OtherMenuOption::Install, "Install Components");
        selections.push(OtherMenuOption::Uninstall, "Uninstall Components");
        selections.push(OtherMenuOption::Interfaces, "List Network Interfaces");
        selections.push(OtherMenuOption::Info, "Show Paths and Installation Info");
        selections.push(OtherMenuOption::Return, "Return");

        match selections.prompt("Select menu option")? {
            None | Some(OtherMenuOption::Return) => break,
            Some(OtherMenuOption::Install) => {
                crate::prompt::report_and_pause("Installation failed", install_with(paths, config))
            }
            Some(OtherMenuOption::Uninstall) => {
                if crate::prompt::confirm_destructive(
                    "Uninstall EveBox, Suricata, and evectl-managed Npcap?",
                ) {
                    crate::prompt::report_and_pause(
                        "Uninstallation failed",
                        uninstall_windows_components(paths),
                    );
                }
            }
            Some(OtherMenuOption::Interfaces) => crate::prompt::report_and_pause(
                "Failed to list network interfaces",
                list_interfaces(),
            ),
            Some(OtherMenuOption::Info) => crate::prompt::report_and_pause(
                "Failed to show project information",
                project_info(paths),
            ),
        }
    }

    Ok(())
}

pub(super) fn project_info(paths: &Paths) -> Result<()> {
    let evebox_install_dir = paths.evebox_install_dir();
    let evebox_exe = find_evebox_exe(&evebox_install_dir)?;
    let evectl_exe = std::env::current_exe().ok();

    println!("Windows path-based directories:");
    println!("  Data root:                 {}", paths.root().display());
    if let Some(evectl_exe) = &evectl_exe {
        println!("  Current EveCtl binary:     {}", evectl_exe.display());
    } else {
        println!("  Current EveCtl binary:     <unknown>");
    }
    println!();

    println!("Config and rules paths in use:");
    println!(
        "  EveCtl config file:        {}",
        paths.config_file().display()
    );
    match configured_interface_value(paths) {
        Ok(Some(interface)) => println!("  Configured interface:      {}", interface),
        Ok(None) => println!("  Configured interface:      <not set>"),
        Err(err) => println!("  Configured interface:      <error: {}>", err),
    }
    match configured_interface_guid(paths) {
        Ok(Some(guid)) => println!("  Resolved interface GUID:   {}", guid),
        Ok(None) => println!("  Resolved interface GUID:   <not set>"),
        Err(err) => println!("  Resolved interface GUID:   <error: {}>", err),
    }
    println!(
        "  Suricata config directory: {}",
        paths.suricata_dir().display()
    );
    println!(
        "  Suricata rules directory:  {}",
        paths.suricata_rules_dir().display()
    );
    println!(
        "  Rule update state:         {}",
        paths.suricata_update_dir().display()
    );
    println!(
        "  Rule update cache:         {}",
        paths.suricata_update_dir().join("cache").display()
    );
    println!();

    println!("Suricata paths in use:");
    println!(
        "  Suricata install dir:      {}",
        paths.suricata_install_dir().display()
    );
    println!(
        "  Suricata logs:             {}",
        paths.suricata_log_dir().display()
    );
    println!(
        "  Suricata packet captures:  {}",
        paths.suricata_pcap_dir().display()
    );
    println!(
        "  Suricata runtime files:    {}",
        paths.suricata_run_dir().display()
    );
    println!();

    println!("Other Windows data paths:");
    println!(
        "  EveBox root directory:     {}",
        paths.evebox_dir().display()
    );
    println!(
        "  EveBox install directory:  {}",
        evebox_install_dir.display()
    );
    println!(
        "  EveBox data directory:     {}",
        paths.evebox_data_dir().display()
    );
    println!(
        "  Selected EveBox channel:   {}",
        load_evectl_config(paths)?.windows.evebox_channel
    );
    println!(
        "  EveBox PID file:           {}",
        Role::EveBoxServer.pid_path(paths).display()
    );
    println!(
        "  EveBox runtime metadata:   {}",
        Role::EveBoxServer.runtime_path(paths).display()
    );
    if let Some(evebox_exe) = evebox_exe {
        println!("  Current EveBox binary:     {}", evebox_exe.display());
        if let Some(version) = evebox_installed_version(&paths.evebox_install_dir())? {
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
