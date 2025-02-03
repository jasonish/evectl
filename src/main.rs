// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{self, Child, Stdio},
    sync::mpsc::Sender,
    thread,
};

use prelude::*;

use clap::{Parser, Subcommand};
use colored::Colorize;
use container::{Container, SuricataContainer};
use logs::LogArgs;
use tracing::Level;

use crate::context::Context;

mod actions;
mod config;
mod configs;
mod container;
mod context;
mod elastic;
mod logs;
mod menu;
mod prelude;
mod prompt;
mod ruleindex;
mod selfupdate;
mod suricata;
mod term;

const SURICATA_CONTAINER_NAME: &str = "evectl-suricata";
const EVEBOX_SERVER_CONTAINER_NAME: &str = "evectl-evebox-server";
const EVEBOX_AGENT_CONTAINER_NAME: &str = "evectl-evebox-agent";

const SURICATA_VOLUME_LOG: &str = "evectl-suricata-log";

fn get_clap_style() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(clap::builder::styling::AnsiColor::Yellow.on_default())
        .usage(clap::builder::styling::AnsiColor::Green.on_default())
        .literal(clap::builder::styling::AnsiColor::Green.on_default())
        .placeholder(clap::builder::styling::AnsiColor::Green.on_default())
}

#[derive(Parser, Debug)]
#[command(styles=get_clap_style())]
struct Args {
    /// Use Podman, by default Docker is used if found
    #[arg(long)]
    podman: bool,

    #[arg(long)]
    no_root: bool,

    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Commands>,
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
    Update,

    /// View the container logs
    Logs(LogArgs),

    #[command(hide = true)]
    Menu {
        menu: String,
    },
}

fn is_interactive(command: &Option<Commands>) -> bool {
    match command {
        Some(command) => match command {
            Commands::Start { debug: _ } => false,
            Commands::Stop => false,
            Commands::Restart => false,
            Commands::Status => false,
            Commands::UpdateRules => false,
            Commands::Update => false,
            Commands::Logs(_) => false,
            Commands::Menu { menu: _ } => true,
        },
        None => true,
    }
}

fn main() -> Result<()> {
    // Mainly for use when developing...
    let _ = std::process::Command::new("stty").args(["sane"]).status();

    let args = Args::parse();
    let is_interactive = is_interactive(&args.command);

    let log_level = if args.verbose > 0 {
        Level::DEBUG
    } else {
        Level::INFO
    };

    if is_interactive {
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .without_time()
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_max_level(log_level).init();
    }

    let data_directory = dirs::data_dir()
        .map(|dir| dir.join("evectl"))
        .ok_or_else(|| anyhow!("Failed to determine data directory"))?;
    let config_directory = dirs::config_dir()
        .map(|dir| dir.join("evectl"))
        .ok_or_else(|| anyhow!("Failed to determine configuration directory"))?;
    let config_file = config_directory.join("config.toml");
    let config = if config_file.exists() {
        crate::config::Config::from_file(&config_file)?
    } else {
        crate::config::Config::default_with_filename(&config_file)
    };

    // Make sure config and data directories exist.
    std::fs::create_dir_all(&config_directory)?;
    std::fs::create_dir_all(&data_directory)?;

    let manager = match container::find_manager(args.podman) {
        Some(manager) => manager,
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
    info!("Found container manager {manager}");

    let mut context = Context::new(config.clone(), config_directory, data_directory, manager);

    let prompt_for_update = {
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

    if prompt_for_update {
        if let Ok(true) =
            inquire::Confirm::new("Required container images not found, download now?")
                .with_default(true)
                .prompt()
        {
            if !update(&context) {
                error!("Failed to downloading container images");
                prompt::enter();
            }
        }
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
                command_start(&context, true)
            }
            Commands::Status => command_status(&context),
            Commands::UpdateRules => {
                if actions::update_rules(&context).is_ok() {
                    0
                } else {
                    1
                }
            }
            Commands::Update => {
                if update(&context) {
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
                "configure.containers" => {
                    menu::containers::menu(&mut context);
                    0
                }
                "configure-suricata" => {
                    menu::suricata::menu(&mut context)?;
                    0
                }
                "evebox-agent" => {
                    menu::evebox_agent::menu(&mut context)?;
                    0
                }
                "evebox-server" => {
                    menu::evebox_server::menu(&mut context)?;
                    0
                }
                _ => panic!("Unhandled menu: {}", menu),
            },
        };
        std::process::exit(code);
    } else {
        menu_main(context)?;
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
        if start_foreground(context).is_err() {
            return 1;
        }
    } else {
        start(context);
    }
    0
}

/// Start EveCtl in the foreground.
///
/// Typically not done from the menus but instead the command line.
fn start_foreground(context: &Context) -> Result<()> {
    let _ = context.manager.stop(SURICATA_CONTAINER_NAME, None);
    context.manager.quiet_rm(SURICATA_CONTAINER_NAME);

    let _ = context.manager.stop(EVEBOX_SERVER_CONTAINER_NAME, None);
    context.manager.quiet_rm(EVEBOX_SERVER_CONTAINER_NAME);

    let _ = context.manager.stop(EVEBOX_AGENT_CONTAINER_NAME, None);
    context.manager.quiet_rm(EVEBOX_AGENT_CONTAINER_NAME);

    elastic::stop_elasticsearch(context);

    let mut children = vec![];

    let (tx, rx) = std::sync::mpsc::channel::<bool>();

    if context.config.suricata.enabled {
        suricata::mkdirs(context)?;
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

    if context.config.elasticsearch.enabled {
        let data_directory = context.data_directory.join("elastic");
        if let Err(err) = std::fs::create_dir_all(&data_directory) {
            error!("Failed to create data directory for Elasticsearch: {}", err);
            return Err(err.into());
        }
        let mut command = elastic::build_docker_command(context, &[]);
        debug!("Starting Elasticsearch: {:?}", &command);
        let mut child = match command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(process) => process,
            Err(err) => {
                error!("Failed to spawn Elasticsearch process: {}", err);
                return Err(err.into());
            }
        };
        process_output_handler(&mut child, "elasticsearch", tx.clone());
        children.push(("elasticsearch", child));
    }

    // Sleep for a moment to give the Elasticsearch container a chance
    // to be created.
    std::thread::sleep(std::time::Duration::from_secs(1));

    if context.config.evebox_server.enabled {
        let mut command = build_evebox_server_command(context, false);
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
        let mut command = build_evebox_agent_command(context, false);
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

    {
        let tx = tx.clone();
        if let Err(err) = ctrlc::set_handler(move || {
            info!("Received Ctrl-C, stopping containers");
            let _ = tx.send(true);
        }) {
            error!("Failed to setup Ctrl-C handler: {}", err);
        }
    }

    if context.config.suricata.enabled {
        let now = std::time::Instant::now();
        loop {
            if !context.manager.is_running(SURICATA_CONTAINER_NAME) {
                if now.elapsed().as_secs() > 3 {
                    error!("Timed out waiting for the Suricata container to start running, not starting log rotation");
                    break;
                } else {
                    continue;
                }
            }

            if let Err(err) = start_suricata_logrotate(context) {
                error!("Failed to start Suricata log rotation: {err}");
            }
            break;
        }
    }

    if children.is_empty() {
        info!("No processes started. Exiting");
        return Ok(());
    }

    let _ = rx.recv();
    let _ = context.manager.stop(SURICATA_CONTAINER_NAME, None);
    let _ = context
        .manager
        .stop(EVEBOX_SERVER_CONTAINER_NAME, Some("SIGINT"));

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

    Ok(())
}

fn stop_container(context: &Context, name: &str) -> bool {
    let mut ok = true;
    if let Err(err) = context.manager.stop(name, None) {
        error!("Failed to stop container {name}: {err}");
        ok = false;
    }
    context.manager.quiet_rm(name);

    ok
}

fn stop_all(context: &Context) -> bool {
    let mut ok = true;

    if context.manager.container_exists(SURICATA_CONTAINER_NAME) {
        info!("Stopping {SURICATA_CONTAINER_NAME}");
        if !stop_container(context, SURICATA_CONTAINER_NAME) {
            ok = false;
        }
    } else {
        info!("Container {SURICATA_CONTAINER_NAME} is not running");
    }

    if context
        .manager
        .container_exists(EVEBOX_SERVER_CONTAINER_NAME)
    {
        info!("Stopping {EVEBOX_SERVER_CONTAINER_NAME}");
        if !stop_container(context, EVEBOX_SERVER_CONTAINER_NAME) {
            ok = false;
        }
    } else {
        info!("Container {EVEBOX_SERVER_CONTAINER_NAME} is not running");
    }

    if context
        .manager
        .container_exists(EVEBOX_AGENT_CONTAINER_NAME)
    {
        info!("Stopping {EVEBOX_AGENT_CONTAINER_NAME}");
        if !stop_container(context, EVEBOX_AGENT_CONTAINER_NAME) {
            ok = false;
        }
    } else {
        info!("Container {EVEBOX_AGENT_CONTAINER_NAME} is not running");
    }

    // Stop Elasticsearch
    info!("Stoping Elasticsearch");
    elastic::stop_elasticsearch(context);

    ok
}

fn command_status(context: &Context) -> i32 {
    let mut code = 0;
    match context.manager.state(SURICATA_CONTAINER_NAME) {
        Ok(state) => info!("suricata: {}", state.status),
        Err(err) => {
            let err = format!("{}", err);
            error!("suricata: {}", err.trim_end());
            code = 1;
        }
    }
    match context.manager.state(EVEBOX_SERVER_CONTAINER_NAME) {
        Ok(state) => info!("evebox: {}", state.status),
        Err(err) => {
            let err = format!("{}", err);
            error!("evebox: {}", err.trim_end());
            code = 1;
        }
    }
    code
}

fn guess_evebox_url(context: &Context) -> String {
    let scheme = if context.config.evebox_server.no_tls {
        "http"
    } else {
        "https"
    };

    if !context.config.evebox_server.allow_remote {
        format!("{}://127.0.0.1:5636", scheme)
    } else {
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
}

fn menu_main(mut context: Context) -> Result<()> {
    loop {
        term::title("EveCtl: Main Menu");

        let suricata_state = if context.config.suricata.enabled {
            context
                .manager
                .state(SURICATA_CONTAINER_NAME)
                .map(|state| state.status)
                .unwrap_or_else(|_| "not running".to_string())
        } else {
            "not enabled".to_string()
        };

        let evebox_server_state = if context.config.evebox_server.enabled {
            let evebox_url = guess_evebox_url(&context);
            context
                .manager
                .state(EVEBOX_SERVER_CONTAINER_NAME)
                .map(|state| {
                    if state.status == "running" {
                        format!("{} {}", state.status, evebox_url,)
                    } else {
                        state.status
                    }
                })
                .unwrap_or_else(|_| "not running".to_string())
        } else {
            "not enabled".to_string()
        };

        let evebox_agent_state = if context.config.evebox_agent.enabled {
            context
                .manager
                .state(EVEBOX_AGENT_CONTAINER_NAME)
                .map(|state| state.status.to_string())
                .unwrap_or_else(|_| "not running".to_string())
        } else {
            "not enabled".to_string()
        };

        let elastic_state = if context.config.elasticsearch.enabled {
            context
                .manager
                .state(elastic::ELASTICSEARCH_CONTAINER_NAME)
                .map(|state| state.status)
                .unwrap_or_else(|_| "not running".to_string())
        } else {
            "not enabled".to_string()
        };

        let running = context.manager.is_running(SURICATA_CONTAINER_NAME)
            || context.manager.is_running(EVEBOX_SERVER_CONTAINER_NAME);

        // TODO: Warn if not running but should be.
        info!("Suricata:      {}", suricata_state);
        info!("EveBox Server: {}", evebox_server_state);
        info!("EveBox Agent:  {}", evebox_agent_state);
        info!("Elasticsearch: {}", elastic_state);

        println!();

        let interface = context
            .config
            .suricata
            .interfaces
            .first()
            .map(String::from)
            .unwrap_or_default();

        let mut selections = prompt::Selections::with_index();
        selections.push("refresh", "Refresh Status");
        if running {
            selections.push("restart", "Restart");
            selections.push("stop", "Stop");
        } else {
            selections.push("start", "Start");
        }
        selections.push(
            "configure-suricata",
            format!(
                "Configure Suricata [enabled={}, interface={}]",
                context.config.suricata.enabled,
                if interface.is_empty() {
                    "None"
                } else {
                    &interface
                }
            ),
        );
        selections.push(
            "configure-evebox-agent",
            format!(
                "Configure EveBox Agent [enabled={}]",
                context.config.evebox_agent.enabled
            ),
        );
        selections.push(
            "configure-evebox-server",
            format!(
                "Configure EveBox Server [enabled={}]",
                context.config.evebox_server.enabled
            ),
        );

        if context.config.suricata.enabled {
            selections.push("suricata-update", "Configure Suricata-Update (Rules)");
        }

        selections.push("update-rules", "Update Rules");
        selections.push("update", "Update");
        selections.push("configure", "Configure");
        selections.push("other", "Other");
        selections.push("exit", "Exit");

        let response = inquire::Select::new("Select a menu option", selections.to_vec())
            .with_page_size(12)
            .prompt();
        match response {
            Ok(selection) => match selection.tag {
                "refresh" => {}
                "start" => {
                    if !start(&context) {
                        prompt::enter();
                    }
                }
                "stop" => {
                    if !stop_all(&context) {
                        prompt::enter();
                    }
                }
                "restart" => {
                    stop_all(&context);
                    if !start(&context) {
                        prompt::enter();
                    }
                }
                "interface" => select_interface(&mut context),
                "update" => {
                    update(&context);
                    prompt::enter();
                }
                "other" => menu::other::menu(&context),
                "configure" => menu::configure::main(&mut context)?,
                "update-rules" => {
                    if let Err(err) = actions::update_rules(&context) {
                        error!("{}", err);
                    }
                    prompt::enter();
                }
                "configure-suricata" => menu::suricata::menu(&mut context)?,
                "configure-evebox-agent" => menu::evebox_agent::menu(&mut context)?,
                "configure-evebox-server" => menu::evebox_server::menu(&mut context)?,
                "suricata-update" => menu::suricata_update::menu(&mut context)?,
                "exit" => break,
                _ => panic!("Unhandled selection: {}", selection.tag),
            },
            Err(_) => break,
        }
    }

    Ok(())
}

/// Returns true if everything started successfully, otherwise false
/// is return.
fn start(context: &Context) -> bool {
    let mut ok = true;

    if context.config.suricata.enabled {
        info!("Starting Suricata");
        if let Err(err) = start_suricata_detached(context) {
            error!("Failed to start Suricata: {}", err);
            ok = false;
        }
    }

    if context.config.elasticsearch.enabled {
        info!("Starting Elasticsearch");
        if let Err(err) = elastic::start_elasticsearch(context) {
            error!("Failed to start Elasticsearch: {}", err);
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

    ok
}

fn build_suricata_command(context: &Context, detached: bool) -> Result<std::process::Command> {
    let config = suricata_dump_config(context)?;
    let mut set_args: Vec<String> = vec![
        "app-layer.protocols.tls.ja4-fingerprints=true".to_string(),
        "app-layer.protocols.quic.ja4-fingerprints=true".to_string(),
    ];
    let patterns = &[
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.tls)\s")?,
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.quic)\s")?,
    ];
    for line in &config {
        for r in patterns {
            if let Some(c) = r.captures(line) {
                set_args.push(format!("{}.ja4=true", &c[1]));
            }
        }
    }

    let interface = match context.config.suricata.interfaces.first() {
        Some(interface) => interface,
        None => bail!("no network interface set"),
    };

    let mut args = ArgBuilder::from(&[
        "run",
        "--name",
        SURICATA_CONTAINER_NAME,
        "--net=host",
        "--cap-add=sys_nice",
        "--cap-add=net_admin",
        "--cap-add=net_raw",
    ]);

    if detached {
        args.add("--detach");
    }

    if let Err(err) = configs::write_af_packet_stub(context) {
        error!("Failed to write af-packet stub: {err}");
    } else {
        let path = context.config_directory.join("af-packet.yaml");
        args.add(format!(
            "--volume={}:/config/af-packet.yaml",
            path.display()
        ));
    }

    for volume in SuricataContainer::new(context.clone()).volumes() {
        args.add(format!("--volume={}", volume));
    }

    args.add(context.image_name(Container::Suricata));
    args.extend(&["-v", "-i", interface]);
    args.add("--include");
    args.add("/config/af-packet.yaml");

    args.add("--set");
    args.add("sensor-name=evectl");

    if let Some(bpf) = &context.config.suricata.bpf {
        args.add(bpf);
    }

    let mut command = context.manager.command();
    command.args(&args.args);
    Ok(command)
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
    context.manager.quiet_rm(SURICATA_CONTAINER_NAME);
    suricata::mkdirs(context)?;
    let mut command = build_suricata_command(context, true)?;
    let output = command.output()?;
    if !output.status.success() {
        bail!(String::from_utf8_lossy(&output.stderr).to_string());
    }

    if let Err(err) = start_suricata_logrotate(context) {
        error!("{}", err);
    }
    Ok(())
}

fn start_suricata_logrotate(context: &Context) -> Result<()> {
    info!("Starting Suricata log rotation");
    match context
        .manager
        .command()
        .args([
            "exec",
            "-d",
            SURICATA_CONTAINER_NAME,
            "bash",
            "-c",
            "while true; do logrotate -v /etc/logrotate.d/suricata > /tmp/last_logrotate 2>&1; sleep 600; done",
        ])
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                bail!(String::from_utf8_lossy(&output.stderr).to_string());
            }
        }
        Err(err) => bail!("Failed to initialize log rotation: {err}"),
    }
    Ok(())
}

fn build_evebox_server_command(context: &Context, daemon: bool) -> process::Command {
    let mut args = ArgBuilder::from(&["run", "--name", EVEBOX_SERVER_CONTAINER_NAME]);
    if context.config.evebox_server.allow_remote {
        args.add("--publish=5636:5636");
    } else {
        args.add("--publish=127.0.0.1:5636:5636");
    }
    if daemon {
        args.add("-d");
    }

    if context.config.elasticsearch.enabled {
        args.add("--link=evectl-elastic");
    }

    args.add(format!(
        "--volume={}:/var/log/suricata",
        context
            .data_directory
            .join("suricata")
            .join("log")
            .display()
    ));

    let host_data_directory = context.data_directory.join("evebox").join("server");
    std::fs::create_dir_all(&host_data_directory).unwrap();
    args.add(format!(
        "--volume={}:/var/lib/evebox",
        host_data_directory.display(),
    ));

    args.add(context.image_name(Container::EveBox));
    args.extend(&["evebox", "server"]);

    if context.config.evebox_server.no_tls {
        args.add("--no-tls");
    }

    if context.config.evebox_server.no_auth {
        args.add("--no-auth");
    }

    args.add("--host=[::0]");

    if context.config.elasticsearch.enabled {
        args.add("--elasticsearch");
        args.add("http://evectl-elastic:9200");
    } else {
        args.add("--sqlite");
    }

    args.add("/var/log/suricata/eve.json");

    let mut command = context.manager.command();
    command.args(&args.args);
    command
}

fn build_evebox_agent_command(context: &Context, detatched: bool) -> process::Command {
    let mut args = ArgBuilder::from(&["run", "--name", EVEBOX_AGENT_CONTAINER_NAME]);
    if detatched {
        args.add("-d");
    }

    let libdir = context.data_directory.join("evebox").join("agent");

    let volumes = vec![
        format!("{}:/var/log/suricata", SURICATA_VOLUME_LOG),
        format!("{}:/var/lib/evebox", libdir.display()),
    ];

    for volume in volumes {
        args.add(format!("--volume={}", volume));
    }

    // For now use host networking. We don't listen on any ports but
    // may need to connect to localhost of the host system.
    args.add("--net=host");

    args.add(context.image_name(Container::EveBox));
    args.extend(&["evebox", "agent"]);

    args.add("--server");
    args.add(&context.config.evebox_agent.server);

    if context.config.evebox_agent.disable_certificate_validation {
        args.add("--disable-certificate-check");
    }

    args.add("/var/log/suricata/eve.json");

    let mut command = context.manager.command();
    command.args(&args.args);
    command
}

fn start_evebox_server_detached(context: &Context) -> Result<()> {
    actions::start_evebox_server(context)
}

fn start_evebox_agent_detached(context: &Context) -> Result<()> {
    actions::start_evebox_agent(context)
}

fn select_interface(context: &mut Context) {
    let interfaces = evectl::system::get_interfaces().unwrap();
    let current_if = context.config.suricata.interfaces.first();
    let index = interfaces
        .iter()
        .position(|interface| Some(&interface.name) == current_if)
        .unwrap_or(0);

    let mut selections = prompt::Selections::with_index();

    for interface in &interfaces {
        let address = interface
            .addr4
            .first()
            .map(|s| format!("-- {}", s.green().italic()))
            .unwrap_or("".to_string());
        selections.push(
            interface.name.to_string(),
            format!("{} {}", &interface.name, address),
        );
    }

    match inquire::Select::new("Select interface", selections.to_vec())
        .with_starting_cursor(index)
        .with_page_size(12)
        .prompt()
    {
        Err(_) => {}
        Ok(selection) => {
            context.config.suricata.interfaces = vec![selection.tag.to_string()];
            let _ = context.config.save();
        }
    }
}

fn update(context: &Context) -> bool {
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
    if let Err(err) = selfupdate::self_update() {
        error!("Failed to update EveCtl: {err}");
        ok = false;
    }
    ok
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
