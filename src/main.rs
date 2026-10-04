#![cfg_attr(windows, allow(dead_code))]

// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use prelude::*;

use clap::Parser;

mod cli;
mod config;
mod configs;
mod container;
mod context;
mod elastic;
mod evebox;
mod fpc;
mod housekeeper;
mod http;
mod logs;
mod menu;
mod prelude;
mod process_output;
mod prompt;
mod ruleindex;
mod rules;
mod selfupdate;
mod services;
mod status;
mod suricata;
mod system;
mod systemd;
mod term;
mod uninstall;
mod update;
mod windows;

// Crate-root names still used by the Windows code.
#[allow(unused_imports)]
pub(crate) use evebox::{
    parse_version as parse_evebox_version, run_version_command as run_evebox_version_command,
};
#[allow(unused_imports)]
pub(crate) use suricata::file_extraction_set_args;

#[cfg(windows)]
fn main() -> Result<()> {
    // Reqwest's rustls-no-provider feature requires installing a crypto
    // provider before any client is built (see Cargo.toml for why ring).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let mut argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if argv.get(1).is_some_and(|arg| arg == "windows") {
        argv.remove(1);
    }

    let args = cli::Args::parse_from(argv);
    let is_worker = matches!(&args.command, Some(windows::Commands::Housekeep { .. }));
    // Internal workers must not consume a staged update instead of doing their job.
    if !is_worker {
        match selfupdate::apply_staged_update_on_startup() {
            Ok(true) => {
                eprintln!(
                    "EveCtl update scheduled after this process exits. Please run your command again."
                );
                return Ok(());
            }
            Ok(false) => {}
            Err(err) => eprintln!("Warning: failed to apply staged EveCtl update: {}", err),
        }
    }

    cli::init_logging(!is_worker, args.verbose);

    let windows_args = windows::Args::from_command(args.command);
    windows::main(windows_args)
}

#[cfg(not(windows))]
fn main() -> Result<()> {
    use container::ContainerManager;

    // Reqwest's rustls-no-provider feature requires installing a crypto
    // provider before any client is built (see Cargo.toml for why ring).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Mainly for use when developing...
    let _ = std::process::Command::new("stty").args(["sane"]).status();

    let args = cli::Args::parse();
    let is_interactive = cli::is_interactive(&args.command);
    cli::init_logging(is_interactive, args.verbose);

    let is_uninstall = matches!(args.command, Some(cli::Commands::Uninstall { .. }));
    let discovered_manager = if is_uninstall {
        container::find_uninstall_manager(args.podman)?
    } else {
        container::find_manager(args.podman)
    };
    let filesystem_only_uninstall = is_uninstall && discovered_manager.is_none();
    let manager = match discovered_manager {
        Some(manager) => {
            info!("Found container manager {manager}");
            manager
        }
        None if is_uninstall => {
            // Both runtime executables are absent, not merely inaccessible.
            // Keep Context's manager placeholder, but explicitly skip runtime
            // discovery/removal in the filesystem-only uninstall path.
            warn!("No container runtime installed; performing filesystem-only uninstall");
            ContainerManager::Docker
        }
        None => {
            error!("No container manager found. Docker or Podman must be available.");
            error!("See https://evebox.org/runtimes/ for more info.");
            std::process::exit(1);
        }
    };
    if manager.is_podman() && system::getuid() != 0 && !args.no_root {
        error!("The Podman container manager requires running as root");
        std::process::exit(1);
    }

    let root = cli::resolve_root(args.data_directory.as_deref())?;
    let config_filename = root.join("evectl.toml");

    // Uninstall must not offer to initialize a new instance.
    if is_uninstall && !config_filename.exists() {
        error!("No EveCtl instance found at {}", root.display());
        std::process::exit(1);
    }

    let context = if config_filename.exists() {
        let config = Config::from_file(&config_filename)?;
        Context::new(config, root, manager)
    } else {
        let prompt = format!(
            "Would you like to initialize a new instance in directory\n    {}",
            root.display()
        );
        if !inquire::Confirm::new(&prompt).with_default(true).prompt()? {
            std::process::exit(0);
        }
        std::fs::create_dir_all(&root)?;
        let config = Config::default_with_filename(&config_filename);
        let mut context = Context::new(config, root, manager);
        menu::wizard::wizard(&mut context)?;
        context
    };

    let code = cli::run(args, context, filesystem_only_uninstall)?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
