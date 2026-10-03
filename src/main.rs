#![cfg_attr(target_os = "windows", allow(dead_code))]

// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{self, Child, Stdio},
    sync::mpsc::Sender,
    thread,
};

use prelude::*;

use clap::{Parser, Subcommand};
use colored::Colorize;
use config::{EveOutput, FileExtractionConfig, FpcConfig};
#[cfg(not(target_os = "windows"))]
use container::ContainerManager;
use container::{Container, RESTART_POLICY_ARG, SuricataContainer};
use logs::LogArgs;
use semver::Version;

const EVE_SOCKET_CONTAINER_PATH: &str = "/var/run/suricata/eve.sock";
const MINIMUM_SURICATA_VERSION: &str = "8.0.6";

mod actions;
mod config;
mod configs;
mod container;
mod context;
mod elastic;
mod evebox;
mod housekeeper;
mod http;
mod logs;
mod menu;
mod prelude;
mod prompt;
mod ruleindex;
mod selfupdate;
mod suricata;
mod systemd;
mod term;
mod uninstall;
mod windows;

fn get_clap_style() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(clap::builder::styling::AnsiColor::Yellow.on_default())
        .usage(clap::builder::styling::AnsiColor::Green.on_default())
        .literal(clap::builder::styling::AnsiColor::Green.on_default())
        .placeholder(clap::builder::styling::AnsiColor::Green.on_default())
}

#[cfg(not(target_os = "windows"))]
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

#[cfg(target_os = "windows")]
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

    #[command(hide = !cfg!(target_os = "windows"))]
    Windows(windows::Args),
}

#[derive(Subcommand, Debug, Clone)]
enum SystemdCommands {
    /// Install and enable systemd service.
    Install,

    /// Remove and de-activate systemd service.
    Remove,
}

#[cfg(not(target_os = "windows"))]
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

#[cfg(not(target_os = "windows"))]
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
#[cfg(not(target_os = "windows"))]
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
    #[cfg(not(target_os = "windows"))]
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

#[cfg(target_os = "windows")]
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

#[cfg(not(target_os = "windows"))]
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
            ContainerManager::Docker(container::DockerManager::new())
        }
        None => {
            error!("No container manager found. Docker or Podman must be available.");
            error!("See https://evebox.org/runtimes/ for more info.");
            std::process::exit(1);
        }
    };
    if manager.is_podman() && evectl::system::getuid() != 0 && !args.no_root {
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
            Commands::Start { debug: detach } => command_start(&context, detach),
            Commands::Stop => {
                if stop_all(&context) {
                    0
                } else {
                    1
                }
            }
            Commands::Restart => {
                stop_all(&context);
                command_start(&context, false)
            }
            Commands::Status => {
                log_status(&context);
                0
            }
            Commands::UpdateRules => {
                if let Err(err) = actions::update_rules(&context, &[]) {
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
                    menu_main(context, &update_continuation_args)?;
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
                    menu::suricata_update::menu(&mut context)?;
                    0
                }
                "configure.containers" => {
                    menu::containers::menu(&mut context);
                    0
                }
                "configure-suricata" => {
                    menu::suricata::menu(&mut context)?;
                    0
                }
                "evebox-agent" => {
                    menu::evebox_agent::menu(&mut context.config)?;
                    0
                }
                "evebox-server" => {
                    menu::evebox_server::menu(&mut context)?;
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
        menu_main(context, &update_continuation_args)?;
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

/// Run when "start" is run from the command line.
fn command_start(context: &Context, debug: bool) -> i32 {
    if debug {
        if let Err(err) = start_foreground(context) {
            error!("Failed to run foreground services: {err:#}");
            return 1;
        }
    } else if !start(context) {
        return 1;
    }
    0
}

fn uses_eve_socket(context: &Context) -> bool {
    context.config.suricata.enabled && context.config.suricata.eve_output == EveOutput::UnixStream
}

/// Full packet capture is in use when the local Suricata is enabled
/// along with the FPC option and something local to serve the spool:
/// the EveBox server directly, or the EveBox agent on behalf of a
/// remote server.
fn uses_fpc(context: &Context) -> bool {
    context.config.suricata.enabled
        && context.config.fpc.enabled
        && (context.config.evebox_server.enabled || context.config.evebox_agent.enabled)
}

/// The FPC configuration as it applies to this start: capture is only
/// enabled if a local EveBox server or agent is there to serve it,
/// otherwise Suricata would fill a spool nothing reads.
fn effective_fpc_config(context: &Context) -> FpcConfig {
    let enabled = uses_fpc(context);
    if context.config.fpc.enabled && !enabled {
        warn!(
            "Full packet capture is enabled but neither the EveBox server nor agent is; not capturing"
        );
    }
    FpcConfig {
        enabled,
        ..context.config.fpc.clone()
    }
}

/// File retrieval follows the local Suricata extraction setting.
fn uses_file_extraction(context: &Context) -> bool {
    context.config.suricata.enabled && context.config.suricata.file_extraction.enabled
}

fn validate_start_configuration(context: &Context) -> Result<()> {
    if !uses_eve_socket(context) {
        return Ok(());
    }

    if context.config.evebox_server.enabled == context.config.evebox_agent.enabled {
        bail!(
            "Unix-stream EVE output requires exactly one local EveBox Server or Agent; enable one or set eve-output = \"file\" under [suricata]"
        );
    }
    Ok(())
}

/// Start EveCtl in the foreground.
///
/// Typically not done from the menus but instead the command line.
fn start_foreground(context: &Context) -> Result<()> {
    info!("Starting services in the foreground");
    validate_start_configuration(context)?;

    let _ = context
        .manager
        .stop(&crate::suricata::container_name(context), None);
    context
        .manager
        .quiet_rm(&crate::suricata::container_name(context));

    let _ = context
        .manager
        .stop(&crate::evebox::server::container_name(context), None);
    context
        .manager
        .quiet_rm(&crate::evebox::server::container_name(context));

    let _ = context
        .manager
        .stop(&crate::evebox::agent::container_name(context), None);
    context
        .manager
        .quiet_rm(&crate::evebox::agent::container_name(context));

    elastic::stop_elasticsearch(context);

    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    {
        let tx = tx.clone();
        ctrlc::set_handler(move || {
            info!("Received shutdown signal, stopping containers");
            let _ = tx.send(true);
        })?;
    }
    let _housekeeper = housekeeper::ForegroundGuard(context);
    housekeeper::reconcile(context)?;

    let mut children = vec![];

    if context.config.elasticsearch_enabled() {
        let engine = context.config.elasticsearch.engine.name();
        if let Err(err) = elastic::create_data_dir(context) {
            error!("Failed to create data directory for {}: {}", engine, err);
            return Err(err);
        }
        let mut command = elastic::build_docker_command(context, false);
        debug!("Starting {}: {:?}", engine, &command);
        let mut child = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(process) => process,
            Err(err) => {
                error!("Failed to spawn {} process: {}", engine, err);
                return Err(err.into());
            }
        };
        process_output_handler(&mut child, engine, tx.clone());
        children.push((engine, child));
    }

    // Sleep for a moment to give the search engine container a chance
    // to be created.
    std::thread::sleep(std::time::Duration::from_secs(1));

    if context.config.evebox_server.enabled {
        let mut command = build_evebox_server_command(context, false)?;
        let mut child = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(process) => process,
            Err(err) => {
                error!("Failed to spawn EveBox-Server process: {}", err);
                return Err(err.into());
            }
        };

        process_output_handler(&mut child, "evebox-server", tx.clone());
        children.push(("evebox-server", child));
    } else {
        info!("EveBox-Server not enabled");
    }

    if context.config.evebox_agent.enabled {
        let mut command = build_evebox_agent_command(context, false)?;
        let mut child = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(process) => process,
            Err(err) => {
                error!("Failed to spawn EveBox-Agent process: {}", err);
                return Err(err.into());
            }
        };

        process_output_handler(&mut child, "evebox-agent", tx.clone());
        children.push(("evebox-agent", child));
    } else {
        info!("EveBox-Agent not enabled");
    }

    if context.config.suricata.enabled {
        suricata::mkdirs(context)?;
        suricata::remove_engine_log(context);
        let mut command = match build_suricata_command(context, false) {
            Ok(command) => command,
            Err(err) => {
                error!("Invalid Suricata configuration: {}", err);
                return Err(err);
            }
        };

        info!("Starting Suricata: {:?}", &command);

        let mut child = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(process) => process,
            Err(err) => {
                error!("Failed to spawn Suricata process: {}", err);
                return Err(err.into());
            }
        };

        process_output_handler(&mut child, "suricata", tx.clone());

        children.push(("suricata", child));
    } else {
        info!("Suricata not enabled");
    }

    if context.config.suricata.enabled
        && let Some(script) = eve_prune_script_for(context)
    {
        let now = std::time::Instant::now();
        loop {
            if !context
                .manager
                .is_running(&crate::suricata::container_name(context))
            {
                if now.elapsed().as_secs() > 3 {
                    error!(
                        "Timed out waiting for the Suricata container to start running, not starting EVE spool pruning"
                    );
                    break;
                } else {
                    continue;
                }
            }

            if let Err(err) = start_eve_prune(context, &script) {
                error!("Failed to start EVE spool pruning: {err}");
            }
            break;
        }
    }

    if housekeeper::enabled(context)
        && !verify_containers_running(
            context,
            &[("Housekeeper", housekeeper::container_name(context))],
        )
    {
        stop_all(context);
        bail!("Housekeeper failed during foreground startup");
    }

    if children.is_empty() {
        info!("No processes started. Exiting");
        return Ok(());
    }

    let _ = rx.recv();
    // Stop housekeeping before waiting on foreground children, including
    // agent-only sessions. Waiting first could leave cleanup running forever.
    let stopped = stop_all(context);

    for (process, mut child) in children {
        match child.wait() {
            Ok(status) => {
                if !status.success() {
                    error!("Process {process} exited with error code {:?}", status);
                }
            }
            Err(err) => {
                error!(
                    "Failed to get exist status for process {process}: {:?}",
                    err
                );
            }
        }
    }

    if !stopped {
        bail!("Failed to stop foreground services");
    }
    Ok(())
}

fn stop_container(context: &Context, name: &str, signal: Option<&str>) -> bool {
    let mut ok = true;
    if context.manager.is_active(name)
        && let Err(err) = context.manager.stop(name, signal)
    {
        error!("Failed to stop container {name}: {err}");
        ok = false;
    }
    context.manager.quiet_rm(name);

    ok
}

fn stop_all(context: &Context) -> bool {
    let mut ok = true;

    if let Err(err) = housekeeper::remove(context) {
        error!("Failed to stop housekeeping: {err}");
        ok = false;
    }

    if context
        .manager
        .container_exists(&crate::suricata::container_name(context))
    {
        info!("Stopping Suricata");
        if !stop_container(context, &crate::suricata::container_name(context), None) {
            ok = false;
        }
    } else {
        debug!(
            "Container {} is not running",
            crate::suricata::container_name(context)
        );
    }

    if context
        .manager
        .container_exists(&crate::evebox::server::container_name(context))
    {
        info!("Stopping EveBox-Server");
        if !stop_container(
            context,
            &crate::evebox::server::container_name(context),
            Some("SIGINT"),
        ) {
            ok = false;
        }
    } else {
        debug!(
            "Container {} is not running",
            &crate::evebox::server::container_name(context)
        );
    }

    // Agent.
    if context
        .manager
        .container_exists(&crate::evebox::agent::container_name(context))
    {
        info!("Stopping EveBox-Agent");
        if !stop_container(
            context,
            &crate::evebox::agent::container_name(context),
            None,
        ) {
            ok = false;
        }
    } else {
        debug!(
            "Container {} is not running",
            crate::evebox::agent::container_name(context)
        );
    }

    // Stop both search engine container names even when the service is
    // disabled, in case it was disabled or changed since the last start.
    let existing_engines = elastic::existing_engines(context);
    if existing_engines.is_empty() {
        debug!("No search engine containers are running");
    } else {
        for engine in existing_engines {
            info!("Stopping {}", engine.name());
        }
    }
    elastic::stop_elasticsearch(context);

    ok
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
        match evectl::system::resolve_interface_or_ip(bind_value) {
            Ok(address) => return format!("{}://{}:5636", scheme, address),
            Err(err) => {
                error!("Failed to resolve bind value {bind_value}: {err}");
            }
        }
    }

    let interfaces = match evectl::system::get_interfaces() {
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

#[derive(Debug, Clone)]
enum Main {
    Refresh,
    Restart,
    Stop,
    SuricataUpdate,
    Start,
    UpdateRules,
    Update,
    Configure,
    Other,
    Exit,
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
            suricata_running_version(context)
        } else {
            suricata_image_version(context)
        };
        let version = match version {
            Ok(Some(version)) if !suricata_version_is_supported(&version) => {
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
        match last_rule_update(context) {
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
            evebox_running_version(context, container_name)
        } else if let Some(version) = &evebox_image_version {
            Ok(Some(version.clone()))
        } else {
            let version = evebox_image_version_query(context);
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

fn menu_main(
    mut context: Context,
    update_continuation_args: &UpdateContinuationArgs,
) -> Result<()> {
    let mut original_config = context.config.clone();

    'outer: loop {
        let running = context
            .manager
            .is_running(&crate::suricata::container_name(&context))
            || context
                .manager
                .is_running(&crate::evebox::server::container_name(&context));

        if context.config != original_config {
            context.config.save()?;

            if let Some(true) = inquire::Confirm::new("Configuration has changed, restart?")
                .with_default(true)
                .prompt_skippable()?
            {
                restart(&context);
                original_config = context.config.clone();
            }
        }

        'inner: loop {
            term::title("EveCtl: Main Menu");

            log_status(&context);
            println!();

            if original_config != context.config {
                warn!("Configuration has changed, restart required");
            }

            let mut selections = prompt::Selections::with_index();
            selections.push(Main::Refresh, "Refresh Status");
            if running {
                selections.push(Main::Restart, "Restart");
                selections.push(Main::Stop, "Stop");
            } else {
                selections.push(Main::Start, "Start");
            }
            if context.config.suricata.enabled {
                selections.push(Main::UpdateRules, "Update Rules");
                selections.push(Main::SuricataUpdate, "Manage Rules");
            }

            selections.push(Main::Update, "Update");
            selections.push(Main::Configure, "Configure");
            selections.push(Main::Other, "Other");
            selections.push(Main::Exit, "Exit");

            let response = inquire::Select::new("Select a menu option", selections.to_vec())
                .with_page_size(12)
                .prompt();
            match response {
                Ok(selection) => match selection.tag {
                    Main::Refresh => {
                        continue 'inner;
                    }
                    Main::Start => {
                        if !start(&context) {
                            prompt::enter();
                        }
                    }
                    Main::Stop => {
                        if !stop_all(&context) {
                            prompt::enter();
                        }
                    }
                    Main::Restart => {
                        restart(&context);
                        original_config = context.config.clone();
                    }
                    Main::Update => {
                        update(&context, update_continuation_args, false, true);
                        prompt::enter();
                    }
                    Main::Other => menu::other::menu(&context),
                    Main::Configure => menu::configure::main(&mut context)?,
                    Main::UpdateRules => {
                        if let Err(err) = actions::update_rules(&context, &[]) {
                            error!("{}", err);
                        }
                        prompt::enter();
                    }
                    Main::SuricataUpdate => menu::suricata_update::menu(&mut context)?,
                    Main::Exit => break 'outer,
                },
                Err(_) => break 'outer,
            }
            continue 'outer;
        }
    }

    Ok(())
}

fn restart(context: &Context) {
    stop_all(context);
    if !start(context) {
        prompt::enter();
    }
}

/// Returns true if everything started successfully, otherwise false
/// is return.
fn start(context: &Context) -> bool {
    if let Err(err) = validate_start_configuration(context) {
        error!("Invalid configuration: {err}");
        return false;
    }

    let mut ok = true;

    if context.config.elasticsearch_enabled() {
        let engine = context.config.elasticsearch.engine.name();
        info!("Starting {}", engine);
        if let Err(err) = elastic::start_elasticsearch(context) {
            error!("Failed to start {}: {}", engine, err);
            ok = false;
        }
    }

    if context.config.evebox_server.enabled {
        info!("Starting EveBox-Server");
        if let Err(err) = start_evebox_server_detached(context) {
            error!("Failed to start EveBox-Server: {}", err);
            ok = false;
        }
    }

    if context.config.evebox_agent.enabled {
        info!("Starting EveBox-Agent");
        if let Err(err) = start_evebox_agent_detached(context) {
            error!("Failed to start EveBox-Agent: {}", err);
            ok = false;
        }
    }

    if context.config.suricata.enabled {
        info!("Starting Suricata");
        if let Err(err) = start_suricata_detached(context) {
            error!("Failed to start Suricata: {}", err);
            ok = false;
        }
    }

    // Reconcile even if Suricata was already running or cleanup was disabled.
    if let Err(err) = housekeeper::reconcile(context) {
        error!("Failed to reconcile housekeeper: {err:#}");
        ok = false;
    }

    let containers = enabled_containers(context);
    if !containers.is_empty() {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if !verify_containers_running(context, &containers) {
            ok = false;
        }
    }

    ok
}

fn enabled_containers(context: &Context) -> Vec<(&'static str, String)> {
    let mut containers = Vec::new();
    if context.config.elasticsearch_enabled() {
        containers.push((
            context.config.elasticsearch.engine.name(),
            elastic::container_name(context),
        ));
    }
    if context.config.evebox_server.enabled {
        containers.push((
            "EveBox-Server",
            crate::evebox::server::container_name(context),
        ));
    }
    if context.config.evebox_agent.enabled {
        containers.push((
            "EveBox-Agent",
            crate::evebox::agent::container_name(context),
        ));
    }
    if context.config.suricata.enabled {
        containers.push(("Suricata", crate::suricata::container_name(context)));
    }
    if housekeeper::enabled(context) {
        containers.push(("Housekeeper", housekeeper::container_name(context)));
    }
    containers
}

fn verify_containers_running(context: &Context, containers: &[(&str, String)]) -> bool {
    let mut ok = true;
    for (label, name) in containers {
        match context.manager.state(name) {
            Ok(state) if state.running && !state.restarting => {
                debug!("{label} container {name} remained running after startup");
            }
            Ok(state) => {
                let detail = if state.error.is_empty() {
                    String::new()
                } else {
                    format!("; error: {}", state.error)
                };
                error!(
                    "{label} container {name} is {}; exit code {}{detail}",
                    state.status, state.exit_code
                );
                ok = false;
            }
            Err(err) => {
                error!("Failed to inspect {label} container {name}: {err}");
                ok = false;
            }
        }
    }
    ok
}

fn build_suricata_command(context: &Context, detached: bool) -> Result<std::process::Command> {
    warn_if_unsupported_suricata_version(context);
    let config = suricata_dump_config(context)?;
    let set_args = suricata_set_args(
        &config,
        context.config.suricata.eve_output,
        &effective_fpc_config(context),
        &context.config.suricata.file_extraction,
    )?;

    let interface = match context.config.suricata.interfaces.first() {
        Some(interface) => interface,
        None => bail!("no network interface set"),
    };

    let mut args = ArgBuilder::from(&[
        "run",
        "--name",
        &crate::suricata::container_name(context),
        "--net=host",
        "--cap-add=sys_nice",
        "--cap-add=net_admin",
        "--cap-add=net_raw",
    ]);

    if detached {
        args.add("--detach");
        args.add(RESTART_POLICY_ARG);
    }

    let path = context.config_dir().join("evectl-suricata.yaml");
    if let Err(err) = configs::write_suricata_stub(&path) {
        error!("Failed to write Suricata include: {err}");
    } else {
        let path = context.config_dir().join("evectl-suricata.yaml");
        args.add(format!(
            "--volume={}",
            context
                .manager
                .bind_mount(&path, "/config/evectl-suricata.yaml")
        ));
    }

    for volume in SuricataContainer::new(context.clone()).volumes() {
        args.add(format!("--volume={}", volume));
    }

    args.add(context.image_name(Container::Suricata));
    args.extend(&["-v", "-i", interface]);
    args.add("--include");
    args.add("/config/evectl-suricata.yaml");

    for set_arg in set_args {
        args.add("--set");
        args.add(set_arg);
    }

    if let Some(sensor_name) = &context.config.suricata.sensor_name {
        args.add("--set");
        args.add(format!("sensor-name={sensor_name}"));
    }

    if let Some(bpf) = &context.config.suricata.bpf {
        args.add(bpf);
    }

    let mut command = context.manager.command();
    command.args(&args.args);
    Ok(command)
}

/// Suricata pcap-log spool directory inside the containers. Shared
/// with the EveBox server and agent through the Suricata log volume.
const PCAP_LOG_CONTAINER_DIR: &str = "/var/log/suricata/pcap";
const PCAP_LOG_PREFIX: &str = "log.";

/// Suricata file-store (extracted files) directory inside the
/// container, on the Suricata log volume.
const FILESTORE_CONTAINER_DIR: &str = "/var/log/suricata/filestore";

fn suricata_set_args(
    config: &[String],
    eve_output: EveOutput,
    fpc: &FpcConfig,
    file_extraction: &FileExtractionConfig,
) -> Result<Vec<String>> {
    let mut set_args: Vec<String> = vec![
        "app-layer.protocols.tls.ja4-fingerprints=true".to_string(),
        "app-layer.protocols.quic.ja4-fingerprints=true".to_string(),
    ];
    let mut eve_log_paths = BTreeSet::new();
    let mut pcap_log_paths = BTreeSet::new();
    let mut file_store_paths = BTreeSet::new();
    let mut disabled_output_paths = BTreeSet::new();
    let output_pattern = regex::Regex::new(r"^(outputs\.\d+) = ([a-zA-Z0-9_-]+)$")?;
    let patterns = &[
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.tls)\s")?,
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.quic)\s")?,
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.dhcp)\s")?,
    ];
    for line in config {
        if let Some(c) = output_pattern.captures(line) {
            let path = format!("{}.{}", &c[1], &c[2]);
            if &c[2] == "eve-log" {
                eve_log_paths.insert(path);
            } else if &c[2] == "pcap-log" && fpc.enabled {
                pcap_log_paths.insert(path);
            } else if &c[2] == "file-store" && file_extraction.enabled {
                file_store_paths.insert(path);
            } else {
                disabled_output_paths.insert(path);
            }
        }

        for r in patterns {
            if let Some(c) = r.captures(line) {
                let path = &c[1];
                if path.ends_with(".dhcp") {
                    set_args.push(format!("{path}.extended=true"));
                } else {
                    set_args.push(format!("{path}.ja4=true"));
                }
            }
        }
    }
    for path in disabled_output_paths {
        set_args.push(format!("{path}.enabled=false"));
    }
    for path in eve_log_paths {
        set_args.push(format!("{path}.suricata-version=true"));
        set_args.push(format!("{path}.enabled=true"));
        if eve_output == EveOutput::UnixStream {
            set_args.push(format!("{path}.threaded=false"));
            set_args.push(format!("{path}.filetype=unix_stream"));
            set_args.push(format!("{path}.filename={EVE_SOCKET_CONTAINER_PATH}"));
        } else {
            // Timestamped spool files, rotated by Suricata and
            // deleted by EveBox once processed.
            set_args.push(format!("{path}.threaded=true"));
            set_args.push(format!("{path}.filename=eve.json.%s"));
            set_args.push(format!("{path}.rotate-interval=minute"));
        }
    }
    if fpc.enabled && pcap_log_paths.is_empty() {
        bail!("full packet capture enabled but Suricata has no pcap-log output");
    }
    for path in pcap_log_paths {
        // Layout expected by EveBox: multi mode with the rotation
        // timestamp in the filename so it can prune by time.
        set_args.push(format!("{path}.enabled=true"));
        set_args.push(format!("{path}.mode=multi"));
        set_args.push(format!("{path}.dir={PCAP_LOG_CONTAINER_DIR}"));
        set_args.push(format!("{path}.filename={PCAP_LOG_PREFIX}%n.%t.pcap"));
        set_args.push(format!("{path}.limit={}", FpcConfig::FILE_SIZE));
        set_args.push(format!(
            "{path}.max-files={}",
            fpc.max_files_per_thread(FpcConfig::capture_threads())
        ));
        set_args.push(format!("{path}.use-stream-depth=no"));
        set_args.push(format!("{path}.honor-pass-rules=no"));
    }
    if file_extraction.enabled {
        set_args.extend(file_extraction_set_args(
            config,
            file_extraction,
            &file_store_paths,
            FILESTORE_CONTAINER_DIR,
        )?);
    }
    Ok(set_args)
}

const HTTP_BODY_LIMITS: [&str; 2] = [
    "app-layer.protocols.http.libhtp.default-config.request-body-limit",
    "app-layer.protocols.http.libhtp.default-config.response-body-limit",
];

/// Overrides to enable the stock file-store output for file
/// extraction, raising the limits that would truncate files below the
/// max extract size. Limits are never lowered.
///
/// - Rule selected files: the file-store stream-depth applies to
///   sessions matching a filestore rule, and replaces the HTTP body
///   limits for them.
/// - Forced storage: the file-store stream-depth is never applied, so
///   the global stream depth and HTTP body limits are raised instead.
fn file_extraction_set_args(
    config: &[String],
    file_extraction: &FileExtractionConfig,
    file_store_paths: &BTreeSet<String>,
    directory: &str,
) -> Result<Vec<String>> {
    if file_store_paths.is_empty() {
        bail!("file extraction enabled but Suricata has no file-store output");
    }

    let max_size = file_extraction.max_size_bytes();
    let current = |key: &str| {
        let prefix = format!("{key} = ");
        config
            .iter()
            .find_map(|line| line.strip_prefix(&prefix))
            .and_then(FileExtractionConfig::parse_size)
    };
    // Unknown values are raised; 0 is unlimited.
    let below_max = |current: Option<u64>| current.is_none_or(|c| c != 0 && c < max_size);
    let stream_depth = current("stream.reassembly.depth");

    let mut set_args = vec![];
    for path in file_store_paths {
        set_args.push(format!("{path}.enabled=true"));
        set_args.push(format!("{path}.version=2"));
        set_args.push(format!("{path}.dir={directory}"));
        set_args.push(format!(
            "{path}.force-filestore={}",
            file_extraction.force_filestore
        ));
        // Redundant with the EVE fileinfo records.
        set_args.push(format!("{path}.write-fileinfo=false"));
        // Suricata ignores a file-store depth not above the global one.
        if !file_extraction.force_filestore && below_max(stream_depth) {
            set_args.push(format!("{path}.stream-depth={max_size}"));
        }
    }
    if file_extraction.force_filestore {
        if below_max(stream_depth) {
            set_args.push(format!("stream.reassembly.depth={max_size}"));
        }
        for key in HTTP_BODY_LIMITS {
            if below_max(current(key)) {
                set_args.push(format!("{key}={max_size}"));
            }
        }
    }
    Ok(set_args)
}

/// Return the time of the last rule update, formatted for display, or
/// None if the rules have never been updated. The time is taken from
/// the rules file written by suricata-update.
fn last_rule_update(context: &Context) -> Option<String> {
    let path = context
        .config_dir()
        .join("suricata")
        .join("lib")
        .join("rules")
        .join("suricata.rules");
    let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
    Some(format_time_with_age(modified, std::time::SystemTime::now()))
}

/// Format a time in the local timezone with a short description of
/// how long ago it was, for example `2026-09-16 00:17 (3 hours ago)`.
fn format_time_with_age(time: std::time::SystemTime, now: std::time::SystemTime) -> String {
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

/// Query the version of EveBox in the named running container.
fn evebox_running_version(context: &Context, container_name: &str) -> Result<Option<String>> {
    let mut command = context.manager.command();
    command.args(["exec", container_name, "evebox", "version"]);
    run_evebox_version_command(command)
}

/// Query the version of EveBox in the configured image by running a
/// throwaway container. Returns None if the image is not present, as
/// running it would trigger a pull.
fn evebox_image_version_query(context: &Context) -> Result<Option<String>> {
    let image = context.image_name(Container::EveBox);
    if !context.manager.has_image(&image) {
        return Ok(None);
    }
    let mut command = context.manager.command();
    command.args(["run", "--rm", &image, "evebox", "version"]);
    run_evebox_version_command(command)
}

fn run_evebox_version_command(mut command: std::process::Command) -> Result<Option<String>> {
    let output = command.output()?;
    if !output.status.success() {
        let message = if output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stdout)
        } else {
            String::from_utf8_lossy(&output.stderr)
        };
        bail!("Failed to query EveBox version: {}", message.trim());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_evebox_version(&stdout))
}

/// Parse the output of `evebox version`, for example
/// `EveBox Version 0.28.0 (rev abcdef0); x86_64-unknown-linux-musl`.
/// Development versions include the revision as they share a version
/// number across builds.
fn parse_evebox_version(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?i)\bEveBox Version\s+(\S+)(?:\s+\(rev\s+([0-9a-f]+)\))?")
        .expect("valid EveBox version regex");
    let captures = re.captures(text)?;
    let version = captures.get(1)?.as_str().to_string();
    match captures.get(2) {
        Some(rev) if version.contains('-') => Some(format!("{version} rev {}", rev.as_str())),
        _ => Some(version),
    }
}

fn parse_suricata_version(text: &str) -> Option<Version> {
    let re = regex::Regex::new(
        r"(?i)\bSuricata(?:\s+version)?\s+([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\b",
    )
    .expect("valid Suricata version regex");
    let version = re.captures(text)?.get(1)?.as_str();
    Version::parse(version).ok()
}

/// Query the Suricata version. If the Suricata container is running,
/// the version is taken from the running container, otherwise a
/// throwaway container is run from the configured image.
fn suricata_version(context: &Context) -> Result<Option<Version>> {
    if context
        .manager
        .is_running(&crate::suricata::container_name(context))
    {
        suricata_running_version(context)
    } else {
        suricata_image_version(context)
    }
}

/// Query the version of Suricata in the running container.
fn suricata_running_version(context: &Context) -> Result<Option<Version>> {
    let mut command = context.manager.command();
    command.args([
        "exec",
        &crate::suricata::container_name(context),
        "suricata",
        "-V",
    ]);
    run_suricata_version_command(command)
}

/// Query the version of Suricata in the configured image by running
/// a throwaway container. Returns None if the image is not present,
/// as running it would trigger a pull.
fn suricata_image_version(context: &Context) -> Result<Option<Version>> {
    let image = context.image_name(Container::Suricata);
    if !context.manager.has_image(&image) {
        return Ok(None);
    }
    let mut command = context.manager.command();
    command.args(["run", "--rm", &image, "-V"]);
    run_suricata_version_command(command)
}

fn run_suricata_version_command(mut command: std::process::Command) -> Result<Option<Version>> {
    let output = command.output()?;
    if !output.status.success() {
        let message = if output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stdout)
        } else {
            String::from_utf8_lossy(&output.stderr)
        };
        bail!("Failed to query Suricata version: {}", message.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(parse_suricata_version(&stdout).or_else(|| parse_suricata_version(&stderr)))
}

fn suricata_version_is_supported(version: &Version) -> bool {
    version >= &Version::new(8, 0, 6)
}

fn warn_if_unsupported_suricata_version(context: &Context) {
    match suricata_version(context) {
        Ok(Some(version)) if !suricata_version_is_supported(&version) => warn!(
            "Suricata {version} is not supported; update the Suricata image to version {MINIMUM_SURICATA_VERSION} or newer"
        ),
        Ok(Some(version)) => debug!("Found Suricata version {version}"),
        Ok(None) => debug!("Could not determine the Suricata version"),
        Err(err) => debug!("Failed to determine the Suricata version: {err}"),
    }
}

fn suricata_dump_config(context: &Context) -> Result<Vec<String>> {
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--rm");
    command.arg(context.image_name(Container::Suricata));
    command.arg("--dump-config");
    let output = command.output()?;
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        let lines: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();
        Ok(lines)
    } else {
        bail!("Failed to run --dump-config for Suricata")
    }
}

fn start_suricata_detached(context: &Context) -> Result<()> {
    let container_name = crate::suricata::container_name(context);
    if context.manager.is_running(&container_name) {
        info!("Suricata is already running");
        return Ok(());
    }
    context.manager.quiet_rm(&container_name);
    suricata::mkdirs(context)?;
    suricata::remove_engine_log(context);
    let mut command = build_suricata_command(context, true)?;
    let output = command.output()?;
    if !output.status.success() {
        bail!(String::from_utf8_lossy(&output.stderr).to_string());
    }

    if let Some(script) = eve_prune_script_for(context)
        && let Err(err) = start_eve_prune(context, &script)
    {
        error!("Failed to start EVE spool pruning: {err}");
    }

    Ok(())
}

/// EVE-only spool backstop. Extracted files are exclusively managed by
/// the housekeeping worker. EveBox normally deletes processed spool files;
/// retain the one-hour backstop for periods without a working consumer.
fn eve_prune_script_for(context: &Context) -> Option<String> {
    (context.config.suricata.eve_output == EveOutput::File).then(|| {
        "while true; do find /var/log/suricata -maxdepth 1 -name 'eve.json.*' ! -name '*.bookmark' -mmin +60 -delete; sleep 300; done".to_string()
    })
}

/// Start the EVE-only spool pruning loop in the Suricata container.
///
/// The loop is an exec'd process, so it does not survive a restart of
/// the container by the container runtime (restart policy); it is only
/// started again when EveCtl (re)starts Suricata.
fn start_eve_prune(context: &Context, script: &str) -> Result<()> {
    info!("Starting EVE spool pruning");
    match context
        .manager
        .command()
        .args([
            "exec",
            "-d",
            &crate::suricata::container_name(context),
            "bash",
            "-c",
            script,
        ])
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                bail!(String::from_utf8_lossy(&output.stderr).to_string());
            }
        }
        Err(err) => bail!("Failed to initialize EVE spool pruning: {err}"),
    }
    Ok(())
}

fn build_evebox_server_command(context: &Context, daemon: bool) -> Result<process::Command> {
    let config = &context.config.evebox_server;
    let use_socket = uses_eve_socket(context);
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--name");
    command.arg(crate::evebox::server::container_name(context));

    if use_socket {
        command.arg("--user=0:998");
    }

    let publish_arg = if context.config.evebox_server.allow_remote {
        if let Some(bind_value) = &config.bind_address {
            let ip = evectl::system::resolve_interface_or_ip(bind_value)?;
            format!("--publish={}:5636:5636", ip)
        } else {
            "--publish=5636:5636".to_string()
        }
    } else {
        "--publish=127.0.0.1:5636:5636".to_string()
    };
    command.arg(publish_arg);

    if daemon {
        command.arg("--detach");
        command.arg(RESTART_POLICY_ARG);
    }

    if context.config.elasticsearch_enabled() {
        command.arg(format!(
            "--link={}",
            crate::elastic::container_name(context)
        ));
    }

    let host_log_directory = context.data_dir().join("suricata").join("log");
    std::fs::create_dir_all(&host_log_directory)?;
    command.arg(format!(
        "--volume={}",
        context
            .manager
            .bind_mount(&host_log_directory, "/var/log/suricata")
    ));

    if use_socket {
        let host_run_directory = context.data_dir().join("suricata").join("run");
        std::fs::create_dir_all(&host_run_directory)?;
        command.arg(format!(
            "--volume={}",
            context
                .manager
                .bind_mount(&host_run_directory, "/var/run/suricata")
        ));
    }

    let host_config_directory = context.config_dir().join("evebox").join("server");
    std::fs::create_dir_all(&host_config_directory)?;
    if use_socket {
        configs::write_evebox_server_socket_config(
            &host_config_directory.join("evectl-input.yaml"),
        )?;
    } else {
        configs::write_evebox_server_file_config(&host_config_directory.join("evectl-input.yaml"))?;
    }
    command.arg(format!(
        "--volume={}",
        context
            .manager
            .bind_mount(&host_config_directory, "/config")
    ));

    let host_data_directory = context.data_dir().join("evebox").join("server");
    std::fs::create_dir_all(&host_data_directory)?;
    command.arg(format!(
        "--volume={}",
        context.manager.bind_mount(&host_data_directory, "/data")
    ));

    command.arg("--env");
    command.arg("EVEBOX_CONFIG_DIRECTORY=/config");

    command.arg("--env");
    command.arg("EVEBOX_DATA_DIRECTORY=/data");

    if config.use_external_elasticsearch {
        if let Some(username) = &config.elasticsearch_client.username {
            command.arg("--env");
            command.arg(format!("EVEBOX_ELASTICSEARCH_USERNAME={}", username));
        }
        if let Some(password) = &config.elasticsearch_client.password {
            command.arg("--env");
            command.arg(format!("EVEBOX_ELASTICSEARCH_PASSWORD={}", password));
        }
        command.arg("--env");
        command.arg(format!(
            "EVEBOX_ELASTICSEARCH_INDEX={}",
            config
                .elasticsearch_client
                .index
                .as_deref()
                .unwrap_or("evebox")
        ));
    } else if context.config.elasticsearch_enabled() {
        // Internal Elasticsearch server.
        command.arg("--env");
        command.arg("EVEBOX_ELASTICSEARCH_INDEX=evebox");
    }

    command.arg(context.image_name(Container::EveBox));
    command.args(["evebox", "server"]);
    command.args(["--config", "/config/evectl-input.yaml"]);

    if context.config.evebox_server.no_tls {
        command.arg("--no-tls");
    }

    if context.config.evebox_server.no_auth {
        command.arg("--no-auth");
    }

    command.arg("--host=[::0]");

    if config.use_external_elasticsearch {
        command.arg("--elasticsearch");
        command.arg(config.elasticsearch_client.url.clone().ok_or_else(|| {
            anyhow::anyhow!("External Elasticsearch URL not set in configuration")
        })?);
        if config.elasticsearch_client.disable_certificate_validation {
            command.arg("--no-check-certificate");
        }
    } else if context.config.elasticsearch_enabled() {
        command.arg("--elasticsearch");
        command.arg(format!(
            "http://{}:9200",
            crate::elastic::container_name(context)
        ));
    } else {
        command.arg("--sqlite");
    }

    command.arg("--data-directory=/data");
    command.arg("--config-directory=/config");

    if uses_fpc(context) {
        command.arg(format!("--pcap-directory={PCAP_LOG_CONTAINER_DIR}"));
        command.arg(format!("--pcap-prefix={PCAP_LOG_PREFIX}"));
    }

    if uses_file_extraction(context) {
        command.arg(format!("--filestore-directory={FILESTORE_CONTAINER_DIR}"));
    }

    Ok(command)
}

fn build_evebox_agent_command(context: &Context, detached: bool) -> Result<process::Command> {
    let use_socket = uses_eve_socket(context);
    let mut args = ArgBuilder::from(&[
        "run",
        "--name",
        &crate::evebox::agent::container_name(context),
    ]);
    if detached {
        args.add("--detach");
        args.add(RESTART_POLICY_ARG);
    }

    if use_socket {
        args.add("--user=0:998");
    }

    let libdir = context.data_dir().join("evebox").join("agent");
    let logdir = context.data_dir().join("suricata").join("log");
    std::fs::create_dir_all(&libdir)?;
    std::fs::create_dir_all(&logdir)?;

    let mut volumes = vec![
        context.manager.bind_mount(&logdir, "/var/log/suricata"),
        context.manager.bind_mount(&libdir, "/var/lib/evebox"),
    ];

    let configdir = context.config_dir().join("evebox").join("agent");
    if use_socket {
        let rundir = context.data_dir().join("suricata").join("run");
        std::fs::create_dir_all(&rundir)?;
        volumes.push(context.manager.bind_mount(&rundir, "/var/run/suricata"));

        configs::write_evebox_agent_socket_config(&configdir.join("evectl-input.yaml"))?;
    } else {
        configs::write_evebox_agent_file_config(&configdir.join("evectl-input.yaml"))?;
    }
    volumes.push(context.manager.bind_mount(&configdir, "/config"));

    for volume in volumes {
        args.add(format!("--volume={}", volume));
    }

    // For now use host networking. We don't listen on any ports but
    // may need to connect to localhost of the host system.
    args.add("--net=host");

    let fpc = uses_fpc(context);
    let file_extraction = uses_file_extraction(context);
    if fpc || file_extraction {
        // The agent key authenticates the file and packet retrieval channel to
        // the server. Passed in the environment, like the server's
        // Elasticsearch credentials, to keep it out of the generated
        // configuration file.
        match &context.config.evebox_agent.key {
            Some(key) => {
                args.add("--env");
                args.add(format!("EVEBOX_SERVER_KEY={key}"));
            }
            None => warn!(
                "File or packet retrieval is enabled but no agent key is set; the EveBox server \
                 will reject the retrieval channel unless it allows unauthenticated agents"
            ),
        }
    }

    args.add(context.image_name(Container::EveBox));
    args.extend(&["evebox", "agent"]);
    args.extend(&["--config", "/config/evectl-input.yaml"]);

    args.add("--server");
    args.add(&context.config.evebox_agent.server);

    if context.config.evebox_agent.disable_certificate_validation {
        args.add("--disable-certificate-check");
    }

    // Stamped on every event and claimed on the retrieval
    // channel, so the server routes file and packet requests for this
    // sensor's events back to this agent.
    if let Some(agent_id) = &context.config.evebox_agent.agent_id {
        args.add("--agent-id");
        args.add(agent_id);
    }

    if fpc {
        args.add(format!("--pcap-directory={PCAP_LOG_CONTAINER_DIR}"));
        args.add(format!("--pcap-prefix={PCAP_LOG_PREFIX}"));
    }

    if file_extraction {
        args.add(format!("--filestore-directory={FILESTORE_CONTAINER_DIR}"));
    }

    let mut command = context.manager.command();
    command.args(&args.args);
    Ok(command)
}

fn start_evebox_server_detached(context: &Context) -> Result<()> {
    actions::start_evebox_server(context)
}

fn start_evebox_agent_detached(context: &Context) -> Result<()> {
    actions::start_evebox_agent(context)
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
        restart(context);
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
    let running = match suricata_running_version(context) {
        Ok(Some(version)) => version,
        Ok(None) => return None,
        Err(err) => {
            debug!("Failed to determine the running Suricata version: {err}");
            return None;
        }
    };
    let image = match suricata_image_version(context) {
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

/// Utility for building arguments for commands.
#[derive(Debug, Default)]
struct ArgBuilder {
    args: Vec<String>,
}

impl ArgBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn from<S: AsRef<str>>(args: &[S]) -> Self {
        let mut builder = Self::default();
        builder.extend(args);
        builder
    }

    fn add(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    fn extend<S: AsRef<str>>(&mut self, args: &[S]) -> &mut Self {
        for arg in args {
            self.args.push(arg.as_ref().to_string());
        }
        self
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
            let interfaces = evectl::system::get_interfaces()?;
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

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn docker_context(config: Config) -> (tempfile::TempDir, Context) {
        let root = tempfile::tempdir().unwrap();
        let context = Context::new(
            config,
            root.path().to_path_buf(),
            ContainerManager::Docker(container::DockerManager::new()),
        );
        (root, context)
    }

    fn command_args(command: &process::Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

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
    fn parses_evebox_versions() {
        assert_eq!(
            parse_evebox_version("EveBox Version 0.28.0 (rev 4884466d); x86_64-unknown-linux-musl"),
            Some("0.28.0".to_string())
        );
        assert_eq!(
            parse_evebox_version(
                "EveBox Version 0.29.0-dev (rev 4884466d); x86_64-unknown-linux-musl"
            ),
            Some("0.29.0-dev rev 4884466d".to_string())
        );
        assert_eq!(
            parse_evebox_version("EveBox Version 0.28.0"),
            Some("0.28.0".to_string())
        );
        assert_eq!(parse_evebox_version("unrecognized output"), None);
    }

    #[test]
    fn parses_and_checks_suricata_versions() {
        assert_eq!(
            parse_suricata_version("This is Suricata version 8.0.6 RELEASE"),
            Some(Version::new(8, 0, 6))
        );
        assert_eq!(
            parse_suricata_version("Suricata 9.0.0-dev"),
            Some(Version::parse("9.0.0-dev").unwrap())
        );
        assert_eq!(parse_suricata_version("unrecognized output"), None);

        assert!(!suricata_version_is_supported(
            &Version::parse("8.0.6-rc1").unwrap()
        ));
        assert!(suricata_version_is_supported(&Version::new(8, 0, 6)));
        assert!(suricata_version_is_supported(&Version::new(9, 0, 0)));
    }

    #[test]
    fn suricata_output_overrides_disable_everything_except_eve_log() {
        let config = [
            "outputs.7 = fast",
            "outputs.7.fast.enabled = yes",
            "outputs.3 = eve-log",
            "outputs.3.eve-log.types.8.tls = (null)",
            "outputs.3.eve-log.types.32.stats = (null)",
            "outputs.12 = stats",
            "outputs.12.stats.enabled = yes",
            "outputs.14 = pcap-log",
            "outputs.14.pcap-log.enabled = no",
            "outputs.15 = file-store",
            "outputs.15.file-store.enabled = no",
            "logging.outputs.1.file.enabled = yes",
            "stream.reassembly.depth = 1 MiB",
            "app-layer.protocols.http.libhtp.default-config.request-body-limit = 100 KiB",
        ]
        .map(str::to_string);

        let set_args = suricata_set_args(
            &config,
            EveOutput::UnixStream,
            &FpcConfig::default(),
            &FileExtractionConfig::default(),
        )
        .unwrap();

        assert!(set_args.contains(&"outputs.7.fast.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.12.stats.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.15.file-store.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.enabled=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.suricata-version=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.threaded=false".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.filetype=unix_stream".to_string()));
        assert!(
            set_args.contains(&"outputs.3.eve-log.filename=/var/run/suricata/eve.sock".to_string())
        );
        assert!(set_args.contains(&"outputs.3.eve-log.types.8.tls.ja4=true".to_string()));
        assert_eq!(
            set_args
                .iter()
                .filter(|arg| arg.ends_with(".enabled=false"))
                .count(),
            4
        );
        assert!(!set_args.contains(&"outputs.3.eve-log.enabled=false".to_string()));
        assert!(!set_args.iter().any(|arg| arg.starts_with("logging.")));
        // Limits are only touched for file extraction.
        assert!(!set_args.iter().any(|arg| arg.starts_with("stream.")));
        assert!(!set_args.iter().any(|arg| arg.contains("body-limit")));
    }

    #[test]
    fn suricata_file_output_configures_timestamped_spool() {
        let config = ["outputs.3 = eve-log"].map(str::to_string);

        let set_args = suricata_set_args(
            &config,
            EveOutput::File,
            &FpcConfig::default(),
            &FileExtractionConfig::default(),
        )
        .unwrap();

        assert!(set_args.contains(&"outputs.3.eve-log.suricata-version=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.enabled=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.threaded=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.filename=eve.json.%s".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.rotate-interval=minute".to_string()));
        assert!(!set_args.iter().any(|arg| arg.contains(".filetype=")));
    }

    #[test]
    fn fpc_configures_pcap_log_for_evebox() {
        let config = [
            "outputs.3 = eve-log",
            "outputs.14 = pcap-log",
            "outputs.14.pcap-log.enabled = no",
        ]
        .map(str::to_string);
        let fpc = FpcConfig {
            enabled: true,
            max_files: Some(20),
        };

        let set_args = suricata_set_args(
            &config,
            EveOutput::UnixStream,
            &fpc,
            &FileExtractionConfig::default(),
        )
        .unwrap();

        assert!(set_args.contains(&"outputs.14.pcap-log.enabled=true".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.mode=multi".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.dir=/var/log/suricata/pcap".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.filename=log.%n.%t.pcap".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.limit=256mb".to_string()));
        let expected = fpc.max_files_per_thread(FpcConfig::capture_threads());
        assert!(set_args.contains(&format!("outputs.14.pcap-log.max-files={expected}")));
        assert!(!set_args.contains(&"outputs.14.pcap-log.enabled=false".to_string()));

        // Without a pcap-log output in the dumped config, FPC can't be set up.
        let config = ["outputs.3 = eve-log"].map(str::to_string);
        assert!(
            suricata_set_args(
                &config,
                EveOutput::UnixStream,
                &fpc,
                &FileExtractionConfig::default()
            )
            .is_err()
        );
    }

    const MB: u64 = 1024 * 1024;

    fn file_extraction_args(file_extraction: FileExtractionConfig) -> Vec<String> {
        let config = [
            "outputs.1 = eve-log",
            "outputs.6 = file-store",
            "outputs.6.file-store.version = 2",
            "outputs.6.file-store.enabled = no",
            "stream.reassembly.depth = 1 MiB",
            "app-layer.protocols.http.libhtp.default-config.request-body-limit = 100 KiB",
            // Unlimited, must not be lowered.
            "app-layer.protocols.http.libhtp.default-config.response-body-limit = 0",
        ]
        .map(str::to_string);
        suricata_set_args(
            &config,
            EveOutput::UnixStream,
            &FpcConfig::default(),
            &FileExtractionConfig {
                enabled: true,
                ..file_extraction
            },
        )
        .unwrap()
    }

    fn has(set_args: &[String], arg: &str) -> bool {
        set_args.iter().any(|a| a == arg)
    }

    #[test]
    fn file_extraction_rule_selected_uses_file_store_depth() {
        let set_args = file_extraction_args(FileExtractionConfig::default());
        for expected in [
            "outputs.6.file-store.enabled=true",
            "outputs.6.file-store.version=2",
            "outputs.6.file-store.dir=/var/log/suricata/filestore",
            "outputs.6.file-store.force-filestore=false",
            "outputs.6.file-store.write-fileinfo=false",
            &format!("outputs.6.file-store.stream-depth={}", 4 * MB),
        ] {
            assert!(has(&set_args, expected), "missing {expected}");
        }
        assert!(!has(&set_args, "outputs.6.file-store.enabled=false"));
        assert!(!set_args.iter().any(|arg| arg.starts_with("stream.")));
        assert!(!set_args.iter().any(|arg| arg.contains("body-limit")));
    }

    #[test]
    fn file_extraction_forced_raises_global_limits() {
        let set_args = file_extraction_args(FileExtractionConfig {
            force_filestore: true,
            ..Default::default()
        });
        let max = 4 * MB;
        assert!(has(&set_args, "outputs.6.file-store.force-filestore=true"));
        assert!(has(&set_args, &format!("stream.reassembly.depth={max}")));
        assert!(has(
            &set_args,
            &format!("app-layer.protocols.http.libhtp.default-config.request-body-limit={max}")
        ));
        assert!(
            !set_args
                .iter()
                .any(|arg| arg.contains("response-body-limit"))
        );
        assert!(!set_args.iter().any(|arg| arg.contains("stream-depth")));
    }

    #[test]
    fn file_extraction_never_lowers_limits() {
        for force_filestore in [false, true] {
            let set_args = file_extraction_args(FileExtractionConfig {
                force_filestore,
                max_size: Some("512kb".to_string()),
                ..Default::default()
            });
            assert!(!set_args.iter().any(|arg| arg.contains("stream-depth")));
            assert!(!set_args.iter().any(|arg| arg.starts_with("stream.")));
        }
    }

    #[test]
    fn file_extraction_requires_file_store_output() {
        let config = ["outputs.1 = eve-log"].map(str::to_string);
        let file_extraction = FileExtractionConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(
            suricata_set_args(
                &config,
                EveOutput::UnixStream,
                &FpcConfig::default(),
                &file_extraction
            )
            .is_err()
        );
    }

    #[test]
    fn prune_script_only_covers_eve_spool() {
        let (_root, mut context) = docker_context(Config::default());
        for extraction in [false, true] {
            for retention in [None, Some(0), Some(19)] {
                context.config.suricata.file_extraction.enabled = extraction;
                context.config.suricata.file_extraction.max_age_days = retention;
                context.config.suricata.eve_output = EveOutput::UnixStream;
                assert_eq!(eve_prune_script_for(&context), None);
                context.config.suricata.eve_output = EveOutput::File;
                let eve = eve_prune_script_for(&context).unwrap();
                assert!(eve.starts_with(
                    "while true; do find /var/log/suricata -maxdepth 1 -name 'eve.json.*'"
                ));
                assert!(eve.contains("! -name '*.bookmark' -mmin +60 -delete"));
                assert!(eve.ends_with("; sleep 300; done"));
                assert!(!eve.contains("filestore"));
                assert!(!eve.contains("suricatactl"));
            }
        }
    }

    #[test]
    fn fpc_requires_local_evebox_server_or_agent() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.fpc.enabled = true;
        config.fpc.max_files = Some(20);
        let (_root, mut context) = docker_context(config);

        // No server or agent: capture is disabled, retention is
        // preserved.
        let fpc = effective_fpc_config(&context);
        assert!(!fpc.enabled);
        assert_eq!(fpc.max_files, Some(20));

        context.config.evebox_server.enabled = true;
        assert!(effective_fpc_config(&context).enabled);

        context.config.evebox_server.enabled = false;
        context.config.evebox_agent.enabled = true;
        assert!(effective_fpc_config(&context).enabled);

        // Both enabled (file mode): each serves the spool to its own
        // server.
        context.config.evebox_server.enabled = true;
        assert!(effective_fpc_config(&context).enabled);
        let args = command_args(&build_evebox_agent_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
        let args = command_args(&build_evebox_server_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
        context.config.evebox_server.enabled = false;

        // Without Suricata there is nothing to capture.
        context.config.suricata.enabled = false;
        assert!(!effective_fpc_config(&context).enabled);
    }

    #[test]
    fn detached_service_commands_use_restart_policies() {
        let mut server_config = Config::default();
        server_config.evebox_server.enabled = true;
        let (_server_root, server_context) = docker_context(server_config);
        let detached = command_args(&build_evebox_server_command(&server_context, true).unwrap());
        assert!(detached.contains(&RESTART_POLICY_ARG.to_string()));
        let foreground =
            command_args(&build_evebox_server_command(&server_context, false).unwrap());
        assert!(!foreground.contains(&RESTART_POLICY_ARG.to_string()));

        let mut agent_config = Config::default();
        agent_config.evebox_agent.enabled = true;
        agent_config.evebox_agent.server = "https://evebox.example".to_string();
        let (_agent_root, agent_context) = docker_context(agent_config);
        let agent = command_args(&build_evebox_agent_command(&agent_context, true).unwrap());
        assert!(agent.contains(&RESTART_POLICY_ARG.to_string()));

        let mut elastic_config = Config::default();
        elastic_config.evebox_server.enabled = true;
        elastic_config.elasticsearch.enabled = true;
        let (_elastic_root, elastic_context) = docker_context(elastic_config);
        let detached = command_args(&elastic::build_docker_command(&elastic_context, true));
        assert!(detached.contains(&RESTART_POLICY_ARG.to_string()));
        assert!(!detached.contains(&"--rm".to_string()));
        let foreground = command_args(&elastic::build_docker_command(&elastic_context, false));
        assert!(!foreground.contains(&RESTART_POLICY_ARG.to_string()));
        assert!(foreground.contains(&"--rm".to_string()));
    }

    #[test]
    fn enabled_containers_matches_configuration() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.evebox_server.enabled = true;
        config.elasticsearch.enabled = true;
        let (_root, context) = docker_context(config);

        let containers = enabled_containers(&context);
        assert_eq!(containers.len(), 3);
        assert!(containers.iter().any(|(label, _)| *label == "Suricata"));
        assert!(
            containers
                .iter()
                .any(|(label, _)| *label == "EveBox-Server")
        );
        assert!(
            containers
                .iter()
                .any(|(label, _)| *label == "Elasticsearch")
        );
    }

    #[test]
    fn enabled_containers_includes_housekeeper_only_when_required() {
        let (_root, mut context) = docker_context(Config::default());
        for suricata in [false, true] {
            for extraction in [false, true] {
                for retention in [0, 7, 19] {
                    context.config.suricata.enabled = suricata;
                    context.config.suricata.file_extraction.enabled = extraction;
                    context.config.suricata.file_extraction.max_age_days = Some(retention);
                    let names = enabled_containers(&context);
                    assert_eq!(
                        names.iter().any(|(label, name)| *label == "Housekeeper"
                            && *name == housekeeper::container_name(&context)),
                        suricata && extraction && retention > 0
                    );
                }
            }
        }
    }

    #[test]
    fn fpc_adds_pcap_flags_to_evebox_server() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.fpc.enabled = true;
        config.evebox_server.enabled = true;
        let (_root, context) = docker_context(config);

        let args = command_args(&build_evebox_server_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-directory=/var/log/suricata/pcap".to_string()));
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));

        let mut context = context;
        context.config.fpc.enabled = false;
        let args = command_args(&build_evebox_server_command(&context, true).unwrap());
        assert!(!args.iter().any(|a| a.starts_with("--pcap-")));
    }

    #[test]
    fn fpc_adds_pcap_flags_and_key_to_evebox_agent() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.fpc.enabled = true;
        config.evebox_agent.enabled = true;
        config.evebox_agent.server = "https://evebox.example".to_string();
        config.evebox_agent.agent_id = Some("sensor-1".to_string());
        config.evebox_agent.key = Some("secret-key".to_string());
        let (_root, context) = docker_context(config);

        let args = command_args(&build_evebox_agent_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-directory=/var/log/suricata/pcap".to_string()));
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
        let agent_id = args.iter().position(|a| a == "--agent-id").unwrap();
        assert_eq!(args[agent_id + 1], "sensor-1");

        // The key is a container environment variable, so it must
        // come before the image name; the agent ID and pcap options
        // are agent arguments, so they must come after.
        let image = args.iter().position(|a| a == "evebox").unwrap() - 1;
        assert!(agent_id > image);
        let key = args
            .iter()
            .position(|a| a == "EVEBOX_SERVER_KEY=secret-key")
            .unwrap();
        assert_eq!(args[key - 1], "--env");
        assert!(key < image);
        let pcap = args
            .iter()
            .position(|a| a == "--pcap-directory=/var/log/suricata/pcap")
            .unwrap();
        assert!(pcap > image);

        // The agent ID stamps events even without packet capture, but
        // the key and pcap options are only passed with it.
        let mut context = context;
        context.config.fpc.enabled = false;
        let args = command_args(&build_evebox_agent_command(&context, true).unwrap());
        assert!(args.contains(&"--agent-id".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("--pcap-")));
        assert!(!args.iter().any(|a| a.starts_with("EVEBOX_SERVER_KEY=")));

        // Without a key the channel is still configured; the server
        // decides whether to accept it.
        context.config.fpc.enabled = true;
        context.config.evebox_agent.key = None;
        let args = command_args(&build_evebox_agent_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("EVEBOX_SERVER_KEY=")));
    }

    #[test]
    fn file_extraction_configures_evebox_server() {
        for eve_output in [EveOutput::File, EveOutput::UnixStream] {
            for detached in [false, true] {
                let mut config = Config::default();
                config.suricata.enabled = true;
                config.suricata.eve_output = eve_output;
                config.suricata.file_extraction.enabled = true;
                config.evebox_server.enabled = true;
                let (_root, mut context) = docker_context(config);

                let args = command_args(&build_evebox_server_command(&context, detached).unwrap());
                let filestore = args
                    .iter()
                    .position(|a| a == "--filestore-directory=/var/log/suricata/filestore")
                    .unwrap();
                assert!(filestore > args.iter().position(|a| a == "server").unwrap());
                assert!(!args.iter().any(|a| a.starts_with("--pcap-")));

                for (suricata, extraction) in [(false, true), (true, false)] {
                    context.config.suricata.enabled = suricata;
                    context.config.suricata.file_extraction.enabled = extraction;
                    let args =
                        command_args(&build_evebox_server_command(&context, detached).unwrap());
                    assert!(!args.iter().any(|a| a.starts_with("--filestore-")));
                }
            }
        }
    }

    #[test]
    fn file_extraction_agent_channel_is_independent_of_fpc() {
        for eve_output in [EveOutput::File, EveOutput::UnixStream] {
            for detached in [false, true] {
                for fpc in [false, true] {
                    for extraction in [false, true] {
                        for suricata in [false, true] {
                            let mut config = Config::default();
                            config.suricata.enabled = suricata;
                            config.suricata.eve_output = eve_output;
                            config.suricata.file_extraction.enabled = extraction;
                            config.fpc.enabled = fpc;
                            config.evebox_agent.enabled = true;
                            config.evebox_agent.agent_id = Some("sensor-1".to_string());
                            config.evebox_agent.key = Some("secret-key".to_string());
                            let (_root, mut context) = docker_context(config);

                            let args = command_args(
                                &build_evebox_agent_command(&context, detached).unwrap(),
                            );
                            let agent = args.iter().position(|a| a == "agent").unwrap();
                            let filestore = args.iter().position(|a| {
                                a == "--filestore-directory=/var/log/suricata/filestore"
                            });
                            assert_eq!(filestore.is_some(), suricata && extraction);
                            if let Some(position) = filestore {
                                assert!(position > agent);
                            }
                            assert_eq!(
                                args.iter().any(|a| a.starts_with("--pcap-directory=")),
                                suricata && fpc
                            );
                            let key = args
                                .iter()
                                .position(|a| a == "EVEBOX_SERVER_KEY=secret-key");
                            assert_eq!(key.is_some(), suricata && (fpc || extraction));
                            if let Some(position) = key {
                                assert_eq!(args[position - 1], "--env");
                                assert!(position < agent - 2);
                            }
                            let id = args.iter().position(|a| a == "--agent-id").unwrap();
                            assert_eq!(args[id + 1], "sensor-1");

                            context.config.evebox_agent.key = None;
                            let args = command_args(
                                &build_evebox_agent_command(&context, detached).unwrap(),
                            );
                            assert!(!args.iter().any(|a| a.starts_with("EVEBOX_SERVER_KEY=")));
                            assert_eq!(
                                args.iter().any(|a| a.starts_with("--filestore-directory=")),
                                suricata && extraction
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn unix_stream_requires_exactly_one_local_consumer() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        let (_root, mut context) = docker_context(config);

        assert!(validate_start_configuration(&context).is_err());

        context.config.evebox_server.enabled = true;
        assert!(validate_start_configuration(&context).is_ok());

        context.config.evebox_agent.enabled = true;
        assert!(validate_start_configuration(&context).is_err());

        context.config.suricata.eve_output = EveOutput::File;
        assert!(validate_start_configuration(&context).is_ok());
    }

    #[test]
    fn evebox_commands_switch_between_socket_and_file_inputs() {
        let mut socket_config = Config::default();
        socket_config.suricata.enabled = true;
        socket_config.evebox_server.enabled = true;
        let (_socket_root, socket_context) = docker_context(socket_config);

        let server = build_evebox_server_command(&socket_context, true).unwrap();
        let server_args = command_args(&server);
        assert!(socket_context.data_dir().join("suricata/log").is_dir());
        assert!(server_args.contains(&"--user=0:998".to_string()));
        assert!(server_args.contains(&"/config/evectl-input.yaml".to_string()));
        assert!(!server_args.contains(&"/var/log/suricata/eve.json".to_string()));
        assert!(
            server_args
                .iter()
                .any(|arg| arg.contains("/data/suricata/run:/var/run/suricata"))
        );

        let mut agent_config = Config::default();
        agent_config.suricata.enabled = true;
        agent_config.evebox_agent.enabled = true;
        agent_config.evebox_agent.server = "https://evebox.example".to_string();
        let (_agent_root, agent_context) = docker_context(agent_config);

        let agent = build_evebox_agent_command(&agent_context, true).unwrap();
        let agent_args = command_args(&agent);
        assert!(agent_args.contains(&"--user=0:998".to_string()));
        assert!(agent_args.contains(&"/config/evectl-input.yaml".to_string()));
        assert!(!agent_args.contains(&"/var/log/suricata/eve.json".to_string()));

        let mut file_config = Config::default();
        file_config.suricata.enabled = true;
        file_config.suricata.eve_output = EveOutput::File;
        file_config.evebox_server.enabled = true;
        let (_file_root, file_context) = docker_context(file_config);

        let file_server = build_evebox_server_command(&file_context, true).unwrap();
        let file_args = command_args(&file_server);
        assert!(!file_args.contains(&"--user=0:998".to_string()));
        assert!(file_args.contains(&"/config/evectl-input.yaml".to_string()));
        assert!(!file_args.contains(&"/var/log/suricata/eve.json".to_string()));
        assert!(
            !file_args
                .iter()
                .any(|arg| arg.contains("/var/run/suricata"))
        );
        let server_input = std::fs::read_to_string(
            file_context
                .config_dir()
                .join("evebox")
                .join("server")
                .join("evectl-input.yaml"),
        )
        .unwrap();
        assert!(server_input.contains("eve.json.[0-9]*"));
        assert!(server_input.contains("delete-spool-files: true"));

        let mut file_agent_config = Config::default();
        file_agent_config.suricata.enabled = true;
        file_agent_config.suricata.eve_output = EveOutput::File;
        file_agent_config.evebox_agent.enabled = true;
        file_agent_config.evebox_agent.server = "https://evebox.example".to_string();
        let (_file_agent_root, file_agent_context) = docker_context(file_agent_config);

        let file_agent = build_evebox_agent_command(&file_agent_context, true).unwrap();
        let file_agent_args = command_args(&file_agent);
        assert!(file_agent_context.data_dir().join("evebox/agent").is_dir());
        assert!(!file_agent_args.contains(&"--user=0:998".to_string()));
        assert!(file_agent_args.contains(&"/config/evectl-input.yaml".to_string()));
        assert!(!file_agent_args.contains(&"/var/log/suricata/eve.json".to_string()));
        let agent_input = std::fs::read_to_string(
            file_agent_context
                .config_dir()
                .join("evebox")
                .join("agent")
                .join("evectl-input.yaml"),
        )
        .unwrap();
        assert!(agent_input.contains("data-directory: /var/lib/evebox"));
        assert!(agent_input.contains("eve.json.[0-9]*"));
        assert!(agent_input.contains("delete-spool-files: true"));
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
        let manager = ContainerManager::Podman(container::PodmanManager::new());

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
