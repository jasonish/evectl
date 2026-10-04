// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use prelude::*;

use clap::Parser;

// Modules only used by the Linux container runtime are not built on
// Windows; modules shared with Windows but carrying container code are
// allowed their unused parts there.
#[cfg_attr(windows, allow(dead_code))]
mod cli;
#[cfg_attr(windows, allow(dead_code))]
mod config;
#[cfg_attr(windows, allow(dead_code))]
mod configs;
#[cfg_attr(windows, allow(dead_code))]
mod container;
#[cfg(not(windows))]
mod container_platform;
#[cfg_attr(windows, allow(dead_code))]
mod context;
#[cfg_attr(windows, allow(dead_code))]
mod elastic;
#[cfg_attr(windows, allow(dead_code))]
mod evebox;
#[cfg_attr(windows, allow(dead_code))]
mod fpc;
#[cfg_attr(windows, allow(dead_code))]
mod housekeeper;
mod http;
#[cfg(not(windows))]
mod logs;
#[cfg_attr(windows, allow(dead_code))]
mod menu;
mod platform;
mod prelude;
mod process_output;
mod prompt;
#[cfg_attr(windows, allow(dead_code))]
mod ruleindex;
#[cfg_attr(windows, allow(dead_code))]
mod rules;
mod selfupdate;
#[cfg_attr(windows, allow(dead_code))]
mod services;
#[cfg_attr(windows, allow(dead_code))]
mod status;
#[cfg_attr(windows, allow(dead_code))]
mod suricata;
#[cfg_attr(windows, allow(dead_code))]
mod system;
#[cfg_attr(windows, allow(dead_code))]
mod systemd;
mod term;
#[cfg_attr(windows, allow(dead_code))]
mod uninstall;
#[cfg_attr(windows, allow(dead_code))]
mod update;
mod windows;

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
        if !prompt::ask(&prompt, true)? {
            std::process::exit(0);
        }
        std::fs::create_dir_all(&root)?;
        let config = Config::default_with_filename(&config_filename);
        let mut context = Context::new(config, root, manager);
        container_platform::wizard(&mut context)?;
        context
    };

    let code = cli::run(args, context, filesystem_only_uninstall)?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
