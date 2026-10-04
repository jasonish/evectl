#![cfg_attr(windows, allow(dead_code))]

// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::{
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{self, Child},
    sync::mpsc::Sender,
    thread,
};

use prelude::*;

use clap::{Parser, Subcommand};
use colored::Colorize;
use container::Container;
#[cfg(not(windows))]
use container::ContainerManager;
use logs::LogArgs;
use semver::Version;

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
mod prompt;
mod ruleindex;
mod rules;
mod selfupdate;
mod services;
mod suricata;
mod system;
mod systemd;
mod term;
mod uninstall;
mod windows;

// Crate-root names still used by the Windows code.
#[allow(unused_imports)]
pub(crate) use evebox::{
    parse_version as parse_evebox_version, run_version_command as run_evebox_version_command,
};
#[allow(unused_imports)]
pub(crate) use suricata::file_extraction_set_args;

fn get_clap_style() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(clap::builder::styling::AnsiColor::Yellow.on_default())
        .usage(clap::builder::styling::AnsiColor::Green.on_default())
        .literal(clap::builder::styling::AnsiColor::Green.on_default())
        .placeholder(clap::builder::styling::AnsiColor::Green.on_default())
}

#[cfg(not(windows))]
#[derive(Parser, Debug)]
#[command(styles=get_clap_style())]
struct Args {
    /// Use Podman, by default Docker is used if found
    #[arg(long)]
    podman: bool,

    #[arg(long)]
    no_root: bool,

    /// Directory holding the configuration and data for an instance
    #[arg(long, short = 'D', global = true, value_name = "DIR")]
    data_directory: Option<PathBuf>,

    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[cfg(windows)]
#[derive(Parser, Debug)]
#[command(styles=get_clap_style())]
struct Args {
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<windows::Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
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

#[derive(Subcommand, Debug, Clone)]
enum SystemdCommands {
    /// Install and enable systemd service.
    Install,

    /// Remove and de-activate systemd service.
    Remove,
}

#[cfg(not(windows))]
fn is_interactive(command: &Option<Commands>) -> bool {
    match command {
        Some(command) => match command {
            Commands::Start { debug: _ } => false,
            Commands::Stop => false,
            Commands::Restart => false,
            Commands::Status => false,
            Commands::UpdateRules => false,
            Commands::Update {
                containers_only,
                return_to_menu,
            } => *containers_only && *return_to_menu,
            Commands::Logs(_) => false,
            Commands::Menu { menu: _ } => true,
            Commands::Version => false,
            Commands::Print { what: _ } => false,
            Commands::Systemd { command: _ } => false,
            Commands::Uninstall { .. } => false,
            Commands::Windows(_) => true,
        },
        None => true,
    }
}

#[cfg(not(windows))]
fn should_prompt_for_missing_images(command: &Option<Commands>) -> bool {
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
fn resolve_root(data_directory: Option<&Path>) -> Result<PathBuf> {
    let root = if let Some(directory) = data_directory {
        std::path::absolute(directory)?
    } else {
        let current_dir = std::env::current_dir()?;
        if current_dir.join("evectl.toml").exists() {
            current_dir
        } else {
            context::default_root()
                .ok_or_else(|| anyhow!("Could not find the configuration directory"))?
        }
    };
    context::validate_root(&root)?;
    Ok(root)
}

#[derive(Debug, Eq, PartialEq)]
struct UpdateContinuationArgs {
    podman: bool,
    no_root: bool,
    data_directory: Option<PathBuf>,
    verbose: u8,
}

impl UpdateContinuationArgs {
    #[cfg(not(windows))]
    fn new(manager: ContainerManager, args: &Args) -> Self {
        Self {
            podman: manager.is_podman(),
            no_root: args.no_root,
            data_directory: args.data_directory.clone(),
            verbose: args.verbose,
        }
    }

    fn to_args(&self, return_to_menu: bool) -> Vec<String> {
        let mut args = vec![];
        if self.podman {
            args.push("--podman".to_string());
        }
        if self.no_root {
            args.push("--no-root".to_string());
        }
        if let Some(directory) = &self.data_directory {
            args.push("--data-directory".to_string());
            args.push(directory.to_string_lossy().to_string());
        }
        for _ in 0..self.verbose {
            args.push("-v".to_string());
        }
        args.push("update".to_string());
        args.push("--containers-only".to_string());
        if return_to_menu {
            args.push("--return-to-menu".to_string());
        }
        args
    }
}

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

    let args = Args::parse_from(argv);
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

    init_logging(!is_worker, args.verbose);

    let windows_args = windows::Args::from_command(args.command);
    windows::main(windows_args)
}

#[cfg(not(windows))]
fn main() -> Result<()> {
    // Reqwest's rustls-no-provider feature requires installing a crypto
    // provider before any client is built (see Cargo.toml for why ring).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Mainly for use when developing...
    let _ = std::process::Command::new("stty").args(["sane"]).status();

    let args = Args::parse();
    let is_interactive = is_interactive(&args.command);
    init_logging(is_interactive, args.verbose);

    let is_uninstall = matches!(args.command, Some(Commands::Uninstall { .. }));
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
    if manager.is_podman() && crate::system::getuid() != 0 && !args.no_root {
        error!("The Podman container manager requires running as root");
        std::process::exit(1);
    }

    let update_continuation_args = UpdateContinuationArgs::new(manager, &args);

    let root = resolve_root(args.data_directory.as_deref())?;
    let config_filename = root.join("evectl.toml");

    // Uninstall must not offer to initialize a new instance.
    if is_uninstall && !config_filename.exists() {
        error!("No EveCtl instance found at {}", root.display());
        std::process::exit(1);
    }

    let mut context = if config_filename.exists() {
        let config = crate::config::Config::from_file(&config_filename)?;
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
        let config = crate::config::Config::default_with_filename(&config_filename);
        let mut context = Context::new(config, root, manager);
        menu::wizard::wizard(&mut context)?;
        context
    };

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
        && let Ok(true) =
            inquire::Confirm::new("Required container images not found, download now?")
                .with_default(true)
                .prompt()
        && !update(&context, &update_continuation_args, false, false)
    {
        error!("Failed to downloading container images");
        prompt::enter();
    }

    if let Some(command) = args.command {
        let code = match command {
            Commands::Start { debug: detach } => services::command_start(&context, detach),
            Commands::Stop => {
                if services::stop_all(&context) {
                    0
                } else {
                    1
                }
            }
            Commands::Restart => {
                services::stop_all(&context);
                services::command_start(&context, false)
            }
            Commands::Status => {
                log_status(&context);
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
            } => {
                let ok = update(
                    &context,
                    &update_continuation_args,
                    containers_only,
                    return_to_menu,
                );
                if return_to_menu {
                    prompt::enter();
                    services::menu_main(context, &update_continuation_args)?;
                    0
                } else if ok {
                    0
                } else {
                    1
                }
            }
            Commands::Logs(args) => {
                logs::logs(&context, args);
                0
            }
            Commands::Menu { menu } => match menu.as_str() {
                "configure" => {
                    menu::configure::main(&mut context)?;
                    0
                }
                "suricata-update" => {
                    menu::rules::menu(&rules::ContainerBackend(&context))?;
                    0
                }
                "configure.containers" => {
                    menu::containers::menu(&mut context);
                    0
                }
                "configure-suricata" => {
                    menu::suricata::container_menu(&mut context)?;
                    0
                }
                "evebox-agent" => {
                    menu::evebox_agent::menu(&mut context.config)?;
                    0
                }
                "evebox-server" => {
                    menu::evebox_server::container_menu(&mut context)?;
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
        std::process::exit(code);
    } else {
        services::menu_main(context, &update_continuation_args)?;
    }

    Ok(())
}

fn process_line_reader<R: Read + Sync + Send + 'static>(
    output: R,
    label: &'static str,
    done: Sender<bool>,
) {
    let reader = BufReader::new(output).lines();
    for line in reader {
        if let Ok(line) = line {
            // Add some coloring to the Suricata output as it
            // doesn't add its own color when writing to a
            // non-interactive terminal.
            let line = if line.starts_with("Info") {
                line.green().to_string()
            } else if line.starts_with("Error") {
                line.red().to_string()
            } else if line.starts_with("Notice") {
                line.magenta().to_string()
            } else if line.starts_with("Warn") {
                line.yellow().to_string()
            } else {
                line.to_string()
            };
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(&mut stdout, "{}: {}", label, line);
            let _ = stdout.flush();
        } else {
            debug!("{}: EOF", label);
            break;
        }
    }
    let _ = done.send(true);
}

fn process_output_handler(child: &mut Child, label: &'static str, tx: Sender<bool>) {
    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        thread::spawn(move || process_line_reader(stdout, label, tx));
    }

    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        thread::spawn(move || process_line_reader(stderr, label, tx));
    }
}

fn guess_evebox_url(context: &Context) -> String {
    let scheme = if context.config.evebox_server.no_tls {
        "http"
    } else {
        "https"
    };

    if !context.config.evebox_server.allow_remote {
        return format!("{}://127.0.0.1:5636", scheme);
    }

    if let Some(bind_value) = &context.config.evebox_server.bind_address {
        match crate::system::resolve_interface_or_ip(bind_value) {
            Ok(address) => return format!("{}://{}:5636", scheme, address),
            Err(err) => {
                error!("Failed to resolve bind value {bind_value}: {err}");
            }
        }
    }

    let interfaces = match crate::system::get_interfaces() {
        Ok(interfaces) => interfaces,
        Err(err) => {
            error!("Failed to get system interfaces: {err}");
            return format!("{}://127.0.0.1:5636", scheme);
        }
    };

    // Find the first interface that is up...
    let mut addr: Option<&String> = None;

    for interface in &interfaces {
        // Only consider IPv4 addresses for now.
        if interface.addr4.is_empty() {
            continue;
        }
        if interface.name == "lo" && addr.is_none() {
            addr = interface.addr4.first();
        } else if interface.status == "UP" {
            match addr {
                Some(previous) => {
                    if previous.starts_with("127") {
                        addr = interface.addr4.first();
                    }
                }
                None => {
                    addr = interface.addr4.first();
                }
            }
        }
    }

    format!(
        "{}://{}:5636",
        scheme,
        addr.unwrap_or(&"127.0.0.1".to_string())
    )
}

fn log_status(context: &Context) {
    let mut status = vec![];
    let mut enabled = 0;

    if context.config.suricata.enabled {
        enabled += 1;
        let running = context
            .manager
            .is_running(&crate::suricata::container_name(context));
        let version = if running {
            suricata::running_version(context)
        } else {
            suricata::image_version(context)
        };
        let version = match version {
            Ok(Some(version)) if !suricata::version_is_supported(&version) => {
                format!(" ({version}, unsupported)")
            }
            Ok(Some(version)) => format!(" ({version})"),
            Ok(None) => String::new(),
            Err(err) => {
                debug!("Failed to determine the Suricata version: {err}");
                String::new()
            }
        };
        if running {
            status.push(("info", "Suricata", format!("running{version}")));
        } else {
            status.push(("warn", "Suricata", format!("not running{version}")));
        }
        match suricata::last_rule_update(context) {
            Some(updated) => status.push(("info", "Rules", format!("updated {updated}"))),
            None => status.push(("warn", "Rules", "never updated".to_string())),
        }
    } else {
        status.push(("debug", "Suricata", "not enabled".to_string()));
    }

    // The EveBox server and agent share an image, so the image version
    // is only queried once if neither is running.
    let mut evebox_image_version: Option<String> = None;
    let mut evebox_version_suffix = |running: bool, container_name: &str| -> String {
        let version = if running {
            evebox::running_version(context, container_name)
        } else if let Some(version) = &evebox_image_version {
            Ok(Some(version.clone()))
        } else {
            let version = evebox::image_version(context);
            if let Ok(Some(version)) = &version {
                evebox_image_version = Some(version.clone());
            }
            version
        };
        match version {
            Ok(Some(version)) => format!(" ({version})"),
            Ok(None) => String::new(),
            Err(err) => {
                debug!("Failed to determine the EveBox version: {err}");
                String::new()
            }
        }
    };

    if context.config.evebox_server.enabled {
        enabled += 1;
        let container_name = crate::evebox::server::container_name(context);
        let running = context.manager.is_running(&container_name);
        let version = evebox_version_suffix(running, &container_name);
        if running {
            let url = guess_evebox_url(context);
            status.push(("info", "EveBox Server", format!("running{version} {url}")));
        } else {
            status.push(("warn", "EveBox Server", format!("not running{version}")));
        }
    } else {
        status.push(("debug", "EveBox Server", "not enabled".to_string()));
    }

    if context.config.evebox_agent.enabled {
        enabled += 1;
        let container_name = crate::evebox::agent::container_name(context);
        let running = context.manager.is_running(&container_name);
        let version = evebox_version_suffix(running, &container_name);
        if running {
            status.push(("info", "EveBox Agent", format!("running{version}")));
        } else {
            status.push(("warn", "EveBox Agent", format!("not running{version}")));
        }
    } else {
        status.push(("debug", "EveBox Agent", "not enabled".to_string()));
    }

    let engine = context.config.elasticsearch.engine.name();
    if context.config.elasticsearch_enabled() {
        enabled += 1;
        if context
            .manager
            .is_running(&elastic::container_name(context))
        {
            status.push(("info", engine, "running".to_string()));
        } else {
            status.push(("warn", engine, "not running".to_string()));
        }
    } else {
        status.push(("debug", engine, "not enabled".to_string()));
    }

    if housekeeper::enabled(context) {
        enabled += 1;
        if context
            .manager
            .is_running(&housekeeper::container_name(context))
        {
            status.push(("info", "Housekeeper", "running".to_string()));
        } else {
            status.push(("warn", "Housekeeper", "not running".to_string()));
        }
    } else if context
        .manager
        .is_active(&housekeeper::container_name(context))
    {
        status.push((
            "warn",
            "Housekeeper",
            "running but disabled; run evectl start or stop".to_string(),
        ));
    }

    for (level, label, state) in &status {
        match *level {
            "info" => info!("{label:-13}: {state}"),
            "warn" => warn!("{label:-13}: {state}"),
            "debug" => debug!("{label:-13}: {state}"),
            _ => {}
        }
    }

    if enabled == 0 {
        info!("No services enabled");
    }
}

/// Format a time in the local timezone with a short description of
/// how long ago it was, for example `2026-09-16 00:17 (3 hours ago)`.
pub(crate) fn format_time_with_age(
    time: std::time::SystemTime,
    now: std::time::SystemTime,
) -> String {
    let mut datetime = time::OffsetDateTime::from(time);
    let format = if let Ok(offset) = time::UtcOffset::current_local_offset() {
        datetime = datetime.to_offset(offset);
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]")
    } else {
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC")
    };
    let formatted = datetime
        .format(format)
        .unwrap_or_else(|_| datetime.to_string());
    let age = now.duration_since(time).unwrap_or_default().as_secs();
    let age = match age {
        0..=59 => "just now".to_string(),
        60..=3599 => format_age(age / 60, "minute"),
        3600..=86399 => format_age(age / 3600, "hour"),
        _ => format_age(age / 86400, "day"),
    };
    format!("{formatted} ({age})")
}

fn format_age(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{count} {unit}s ago")
    }
}

fn update(
    context: &Context,
    update_continuation_args: &UpdateContinuationArgs,
    containers_only: bool,
    return_to_menu: bool,
) -> bool {
    if containers_only {
        return update_containers(context, return_to_menu);
    }

    match selfupdate::self_update() {
        Ok(selfupdate::SelfUpdate::Unchanged) => update_containers(context, return_to_menu),
        Ok(selfupdate::SelfUpdate::Updated(current_exe)) => {
            std::process::exit(continue_update_with_new_binary(
                &current_exe,
                update_continuation_args,
                return_to_menu,
            ));
        }
        Err(err) => {
            error!("Failed to update EveCtl: {err}");
            info!("Continuing with container updates");
            update_containers(context, return_to_menu);
            false
        }
    }
}

/// Offer to restart Suricata after an update changed its version.
fn prompt_restart_for_updated_suricata(context: &Context, running: &Version, image: &Version) {
    let message = format!("Suricata updated from {running} to {image}, restart now?");
    if let Ok(Some(true)) = inquire::Confirm::new(&message)
        .with_default(true)
        .prompt_skippable()
    {
        services::restart(context);
    }
}

/// If Suricata is running and its version differs from the version
/// in the configured image, return the running and image versions.
fn suricata_update_pending(context: &Context) -> Option<(Version, Version)> {
    if !context.config.suricata.enabled
        || !context
            .manager
            .is_running(&crate::suricata::container_name(context))
    {
        return None;
    }
    let running = match suricata::running_version(context) {
        Ok(Some(version)) => version,
        Ok(None) => return None,
        Err(err) => {
            debug!("Failed to determine the running Suricata version: {err}");
            return None;
        }
    };
    let image = match suricata::image_version(context) {
        Ok(Some(version)) => version,
        Ok(None) => return None,
        Err(err) => {
            debug!("Failed to determine the Suricata image version: {err}");
            return None;
        }
    };
    if running != image {
        Some((running, image))
    } else {
        None
    }
}

/// Pull the container images. If the running Suricata version differs
/// from the image afterwards, offer a restart when interactive,
/// otherwise log that a restart is required.
fn update_containers(context: &Context, interactive: bool) -> bool {
    let mut ok = true;
    for image in [
        context.image_name(Container::Suricata),
        context.image_name(Container::EveBox),
    ] {
        if let Err(err) = context.manager.pull(&image) {
            error!("Failed to pull {image}: {err}");
            ok = false;
        }
    }
    if context.config.elasticsearch_enabled() {
        let image = elastic::docker_image(context);
        if let Err(err) = context.manager.pull(image) {
            error!("Failed to pull {image}: {err}");
            ok = false;
        }
    }
    if housekeeper::enabled(context) {
        info!("Housekeeper will use the updated Suricata image on the next evectl start/restart");
    }
    if let Some((running, image)) = suricata_update_pending(context) {
        if interactive {
            prompt_restart_for_updated_suricata(context, &running, &image);
        } else {
            info!("Suricata updated from {running} to {image}, restart required");
        }
    }
    ok
}

fn continue_update_with_new_binary(
    current_exe: &Path,
    update_continuation_args: &UpdateContinuationArgs,
    return_to_menu: bool,
) -> i32 {
    let args = update_continuation_args.to_args(return_to_menu);
    info!("Continuing update with {}", current_exe.display());
    let status = process::Command::new(current_exe).args(&args).status();
    match status {
        Ok(status) if status.success() => 0,
        Ok(status) => status.code().unwrap_or(1),
        Err(err) => {
            error!("Failed to continue update with new EveCtl: {err}");
            1
        }
    }
}

fn init_logging(is_interactive: bool, verbose: u8) {
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
                systemd::format_template(&context.root, context.manager)?
            );
        }
        _ => {
            error!("Unknown print target: {}", what);
        }
    }
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn formats_time_with_age() {
        use std::time::{Duration, SystemTime};
        let now = SystemTime::now();
        let ends_with = |t: SystemTime, suffix: &str| {
            let formatted = format_time_with_age(t, now);
            assert!(formatted.ends_with(suffix), "{formatted}");
        };
        ends_with(now, "(just now)");
        ends_with(now - Duration::from_secs(60), "(1 minute ago)");
        ends_with(now - Duration::from_secs(5 * 60), "(5 minutes ago)");
        ends_with(now - Duration::from_secs(3600), "(1 hour ago)");
        ends_with(now - Duration::from_secs(3 * 3600), "(3 hours ago)");
        ends_with(now - Duration::from_secs(2 * 86400), "(2 days ago)");
        // A file time in the future should not panic.
        ends_with(now + Duration::from_secs(60), "(just now)");
    }

    #[test]
    fn update_continuation_args_preserve_runtime_flags() {
        let args = Args::try_parse_from([
            "evectl",
            "--no-root",
            "-vv",
            "-D",
            "/var/lib/evectl-test",
            "update",
        ])
        .expect("parse args");
        let manager = ContainerManager::Podman;

        assert_eq!(
            UpdateContinuationArgs::new(manager, &args),
            UpdateContinuationArgs {
                podman: true,
                no_root: true,
                data_directory: Some(PathBuf::from("/var/lib/evectl-test")),
                verbose: 2,
            }
        );
        assert_eq!(
            UpdateContinuationArgs::new(manager, &args).to_args(false),
            vec![
                "--podman",
                "--no-root",
                "--data-directory",
                "/var/lib/evectl-test",
                "-v",
                "-v",
                "update",
                "--containers-only",
            ]
        );
    }

    #[test]
    fn update_continuation_args_omit_default_flags() {
        let args = UpdateContinuationArgs {
            podman: false,
            no_root: false,
            data_directory: None,
            verbose: 0,
        };

        assert_eq!(args.to_args(false), vec!["update", "--containers-only"]);
        assert_eq!(
            args.to_args(true),
            vec!["update", "--containers-only", "--return-to-menu"]
        );
    }

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
        })));
        assert!(!should_prompt_for_missing_images(&Some(Commands::Update {
            containers_only: true,
            return_to_menu: true,
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
    }

    #[test]
    fn update_menu_continuation_is_interactive() {
        assert!(is_interactive(&Some(Commands::Update {
            containers_only: true,
            return_to_menu: true,
        })));
        assert!(!is_interactive(&Some(Commands::Update {
            containers_only: true,
            return_to_menu: false,
        })));
        assert!(!is_interactive(&Some(Commands::Update {
            containers_only: false,
            return_to_menu: true,
        })));
    }
}
