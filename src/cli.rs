// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Command line arguments and command dispatch.

#[cfg(not(windows))]
use std::path::{Path, PathBuf};

use clap::Parser;
#[cfg(not(windows))]
use clap::Subcommand;

#[cfg(not(windows))]
use crate::logs::LogArgs;
#[cfg(not(windows))]
use crate::prelude::*;
use crate::windows;

pub(crate) fn get_clap_style() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(clap::builder::styling::AnsiColor::Yellow.on_default())
        .usage(clap::builder::styling::AnsiColor::Green.on_default())
        .literal(clap::builder::styling::AnsiColor::Green.on_default())
        .placeholder(clap::builder::styling::AnsiColor::Green.on_default())
}

#[cfg(not(windows))]
#[derive(Parser, Debug)]
#[command(styles=get_clap_style())]
pub(crate) struct Args {
    /// Use Podman, by default Docker is used if found
    #[arg(long)]
    pub(crate) podman: bool,

    #[arg(long)]
    pub(crate) no_root: bool,

    /// Directory holding the configuration and data for an instance
    #[arg(long, short = 'D', global = true, value_name = "DIR")]
    pub(crate) data_directory: Option<PathBuf>,

    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[cfg(windows)]
#[derive(Parser, Debug)]
#[command(styles=get_clap_style())]
pub(crate) struct Args {
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Option<windows::Commands>,
}

#[cfg(not(windows))]
#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Start enabled services
    Start {
        /// Run in the foreground, mainly for debugging
        #[arg(long, short)]
        debug: bool,
    },

    /// Stop all services
    Stop,

    /// Stop and start all services
    Restart,

    /// Display status of each service.
    Status,

    /// Update Suricata rules (if Suricata enabled)
    UpdateRules,

    /// Update containers and EveCtl itself.
    Update {
        /// Restart all enabled services after a successful update (interrupts monitoring)
        #[arg(long)]
        restart: bool,
        #[arg(long, hide = true)]
        containers_only: bool,
        #[arg(long, hide = true)]
        return_to_menu: bool,
    },

    /// View the container logs
    Logs(LogArgs),

    /// Display EveCtl version
    Version,

    /// Print details.
    Print { what: String },

    /// Systemd commands.
    Systemd {
        #[command(subcommand)]
        command: SystemdCommands,
    },

    /// Stop all services and remove the instance's data
    Uninstall {
        /// Also remove the configuration directory and evectl.toml
        #[arg(long)]
        config: bool,

        /// Remove everything: configuration, container images, the
        /// systemd unit, and the EveCtl binary
        #[arg(long)]
        all: bool,

        /// Do not prompt for confirmation
        #[arg(long, short)]
        yes: bool,
    },

    #[command(hide = true)]
    Menu { menu: String },

    #[command(hide = !cfg!(windows))]
    Windows(windows::Args),
}

#[cfg(not(windows))]
#[derive(Subcommand, Debug, Clone)]
pub(crate) enum SystemdCommands {
    /// Install and enable systemd service.
    Install,

    /// Remove and de-activate systemd service.
    Remove,
}

/// True if the command runs a menu, so logging should be formatted
/// for a terminal rather than a log file.
#[cfg(not(windows))]
pub(crate) fn is_interactive(command: &Option<Commands>) -> bool {
    matches!(
        command,
        None | Some(Commands::Menu { .. })
            | Some(Commands::Windows(_))
            | Some(Commands::Update {
                containers_only: true,
                return_to_menu: true,
                ..
            })
    )
}

#[cfg(not(windows))]
pub(crate) fn should_prompt_for_missing_images(command: &Option<Commands>) -> bool {
    !matches!(
        command,
        Some(Commands::Update { .. }) | Some(Commands::Uninstall { .. })
    )
}

/// Resolve the instance root directory.
///
/// An explicit --data-directory always wins. Otherwise an
/// `evectl.toml` in the current directory is respected for
/// compatibility with existing instances, falling back to the
/// platform configuration directory (e.g., ~/.config/evectl).
#[cfg(not(windows))]
pub(crate) fn resolve_root(data_directory: Option<&Path>) -> Result<PathBuf> {
    let root = if let Some(directory) = data_directory {
        std::path::absolute(directory)?
    } else {
        let current_dir = std::env::current_dir()?;
        if current_dir.join("evectl.toml").exists() {
            current_dir
        } else {
            crate::context::default_root()
                .ok_or_else(|| anyhow!("Could not find the configuration directory"))?
        }
    };
    crate::context::validate_root(&root)?;
    Ok(root)
}

pub(crate) fn init_logging(is_interactive: bool, verbose: u8) {
    let log_level = if verbose > 0 {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    if is_interactive {
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .without_time()
            .with_target(false)
            .init();
    } else {
        use time::macros::format_description;

        let is_utc = if let Ok(offset) = time::UtcOffset::current_local_offset() {
            offset == time::UtcOffset::UTC
        } else {
            false
        };

        let format = if is_utc {
            format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
        } else {
            format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second][offset_hour sign:mandatory][offset_minute]"
            )
        };

        let timer = tracing_subscriber::fmt::time::LocalTime::new(format);
        tracing_subscriber::fmt()
            .with_timer(timer)
            .with_max_level(log_level)
            .init();
    }
}

#[cfg(not(windows))]
fn print(context: &Context, what: String) -> Result<()> {
    match what.as_str() {
        "interfaces" => {
            let interfaces = crate::system::get_interfaces()?;
            for interface in &interfaces {
                let mut addrs = interface.addr4.clone();
                addrs.extend(interface.addr6.clone());
                let addrs = addrs.join(", ");
                println!("{} {} {}", interface.name, interface.status, addrs);
            }
        }
        "systemd" => {
            println!(
                "{}",
                crate::systemd::format_template(&context.root, context.manager)?
            );
        }
        _ => {
            error!("Unknown print target: {}", what);
        }
    }
    Ok(())
}

/// Run the command, or the main menu if none was given, returning the
/// process exit code. `filesystem_only_uninstall` is set when no
/// container runtime is installed at all.
#[cfg(not(windows))]
pub(crate) fn run(
    args: Args,
    mut context: Context,
    filesystem_only_uninstall: bool,
) -> Result<i32> {
    use crate::update::{UpdateContinuationArgs, update};
    use crate::{container_platform, menu, prompt, rules, services, systemd, uninstall};

    let manager = context.manager;
    let update_continuation_args = UpdateContinuationArgs::new(manager, &args, &context.root);

    let prompt_for_update = should_prompt_for_missing_images(&args.command) && {
        let mut not_found = false;
        if !manager.has_image(&context.suricata_image) {
            info!("Suricata image {} not found", &context.suricata_image);
            not_found = true;
        }
        if !manager.has_image(&context.evebox_image) {
            info!("EveBox image {} not found", &context.evebox_image);
            not_found = true
        }
        not_found
    };

    if prompt_for_update
        && prompt::confirm("Required container images not found, download now?")
        && !update(&context, &update_continuation_args, false, false, false)
    {
        error!("Failed to downloading container images");
        prompt::enter();
    }

    let Some(command) = args.command else {
        container_platform::menu_main(context, &update_continuation_args)?;
        return Ok(0);
    };

    let code = match command {
        Commands::Start { debug: detach } => services::command_start(&context, detach),
        Commands::Stop => {
            if services::stop_all(&context) {
                0
            } else {
                1
            }
        }
        Commands::Restart => match services::restart(&context) {
            Ok(()) => 0,
            Err(err) => {
                error!("Failed to restart services: {err:#}");
                1
            }
        },
        Commands::Status => {
            crate::status::log_status(&context);
            if crate::restart_notice::pending(&context.root) {
                warn!(
                    "Updates applied, but services have not been restarted. Restart is recommended."
                );
            }
            0
        }
        Commands::UpdateRules => {
            if let Err(err) = rules::update_rules(&context, &[]) {
                error!("Failed to update rules: {}", err);
                1
            } else {
                0
            }
        }
        Commands::Update {
            containers_only,
            return_to_menu,
            restart,
        } => {
            let ok = update(
                &context,
                &update_continuation_args,
                containers_only,
                return_to_menu,
                restart,
            );
            if return_to_menu {
                prompt::enter();
                container_platform::menu_main(context, &update_continuation_args)?;
            }
            if ok { 0 } else { 1 }
        }
        Commands::Logs(args) => {
            crate::logs::logs(&context, args);
            0
        }
        Commands::Menu { menu } => match menu.as_str() {
            "configure" => {
                container_platform::configure_menu(&mut context)?;
                0
            }
            "suricata-update" => {
                menu::rules::menu(&container_platform::ContainerBackend::new(&context))?;
                0
            }
            "configure.containers" => {
                menu::containers::menu(&mut context);
                0
            }
            "configure-suricata" => {
                container_platform::suricata_menu(&mut context)?;
                0
            }
            "evebox-agent" => {
                menu::evebox_agent::menu(&mut context.config)?;
                0
            }
            "evebox-server" => {
                container_platform::evebox_server_menu(&mut context)?;
                0
            }
            _ => panic!("Unhandled menu: {}", menu),
        },
        Commands::Version => {
            // Display version and exit.
            println!("{}", env!("EVECTL_VERSION"));
            0
        }
        Commands::Print { what } => {
            print(&context, what)?;
            0
        }
        Commands::Systemd { command } => {
            match command {
                SystemdCommands::Install => systemd::install(&context.root, context.manager)?,
                SystemdCommands::Remove => systemd::remove()?,
            }
            0
        }
        Commands::Uninstall { config, all, yes } => {
            match uninstall::uninstall(&context, config, all, yes, filesystem_only_uninstall) {
                Ok(true) => 0,
                Ok(false) => 1,
                Err(err) => {
                    error!("Uninstall failed: {:#}", err);
                    1
                }
            }
        }
        Commands::Windows(_) => {
            error!("The windows command is only available on Windows");
            1
        }
    };
    Ok(code)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn resolve_root_prefers_explicit_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        let instance = dir.path().join("sensor1");
        let root = resolve_root(Some(&instance)).unwrap();
        assert_eq!(root, instance);
        assert!(root.is_absolute());

        // Directory names that can't form a container name are
        // rejected up front.
        assert!(resolve_root(Some(&dir.path().join("my sensor"))).is_err());
    }

    #[test]
    fn uninstall_command_parses_flags() {
        let args = Args::try_parse_from(["evectl", "uninstall"]).expect("parse args");
        assert!(matches!(
            args.command,
            Some(Commands::Uninstall {
                config: false,
                all: false,
                yes: false,
            })
        ));

        let args = Args::try_parse_from(["evectl", "uninstall", "--config", "--all", "-y"])
            .expect("parse args");
        let command = args.command.expect("uninstall command");
        assert!(matches!(
            command,
            Commands::Uninstall {
                config: true,
                all: true,
                yes: true,
            }
        ));

        // Uninstall must never prompt to download missing images or
        // initialize logging as an interactive menu.
        assert!(!should_prompt_for_missing_images(&Some(command)));
        assert!(!is_interactive(&Some(Commands::Uninstall {
            config: false,
            all: false,
            yes: false,
        })));
    }

    #[test]
    fn update_commands_skip_missing_image_prompt() {
        assert!(!should_prompt_for_missing_images(&Some(Commands::Update {
            containers_only: false,
            return_to_menu: false,
            restart: false,
        })));
        assert!(!should_prompt_for_missing_images(&Some(Commands::Update {
            containers_only: true,
            return_to_menu: true,
            restart: true,
        })));
        assert!(should_prompt_for_missing_images(&Some(Commands::Status)));
        assert!(should_prompt_for_missing_images(&None));
    }

    #[test]
    fn containers_only_flag_parses_but_is_hidden() {
        let args =
            Args::try_parse_from(["evectl", "update", "--containers-only", "--return-to-menu"])
                .expect("parse args");
        assert!(matches!(
            args.command,
            Some(Commands::Update {
                containers_only: true,
                return_to_menu: true,
                restart: false,
            })
        ));

        let mut command = Args::command();
        let update = command
            .find_subcommand_mut("update")
            .expect("update subcommand");
        let mut help = Vec::new();
        update.write_long_help(&mut help).expect("write help");
        let help = String::from_utf8(help).expect("help is utf8");

        assert!(!help.contains("containers-only"));
        assert!(!help.contains("return-to-menu"));
        assert!(help.contains("--restart"));
    }

    #[test]
    fn update_menu_continuation_is_interactive() {
        assert!(is_interactive(&Some(Commands::Update {
            containers_only: true,
            return_to_menu: true,
            restart: false,
        })));
        assert!(!is_interactive(&Some(Commands::Update {
            containers_only: true,
            return_to_menu: false,
            restart: true,
        })));
        assert!(!is_interactive(&Some(Commands::Update {
            containers_only: false,
            return_to_menu: true,
            restart: false,
        })));
        assert!(is_interactive(&None));
        assert!(is_interactive(&Some(Commands::Menu {
            menu: "configure".to_string()
        })));
        assert!(!is_interactive(&Some(Commands::Status)));
    }
}
