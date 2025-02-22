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

mod actions;
mod config;
mod configs;
mod container;
mod context;
mod elastic;
mod evebox;
mod logs;
mod menu;
mod prelude;
mod prompt;
mod ruleindex;
mod selfupdate;
mod suricata;
mod systemd;
mod term;

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

    /// Display EveCtl version
    Version,

    /// Print details.
    Print { what: String },

    /// Systemd commands.
    Systemd {
        #[command(subcommand)]
        command: SystemdCommands,
    },

    #[command(hide = true)]
    Menu { menu: String },
}

#[derive(Subcommand, Debug, Clone)]
enum SystemdCommands {
    /// Install and enable systemd service.
    Install,

    /// Remove and de-activate systemd service.
    Remove,
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
            Commands::Version => false,
            Commands::Print { what: _ } => false,
            Commands::Systemd { command: _ } => false,
        },
        None => true,
    }
}

fn main() -> Result<()> {
    // Mainly for use when developing...
    let _ = std::process::Command::new("stty").args(["sane"]).status();

    let args = Args::parse();
    let is_interactive = is_interactive(&args.command);
    init_logging(is_interactive, args.verbose);

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

    let root = std::env::current_dir()?;

    // Config file path name. For now we use `evectl.toml` in the
    // current directory. But the Freedesktop.org way would be
    // ~/.config/evectl/config.toml.
    let config_filename = root.join("evectl.toml");

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
        let config = crate::config::Config::default_with_filename(&config_filename);
        let mut context = Context::new(config, root, manager);
        menu::wizard::wizard(&mut context)?;
        context
    };

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
            Commands::Status => {
                log_status(&context);
                0
            }
            Commands::UpdateRules => {
                if let Err(err) = actions::update_rules(&context) {
                    error!("Failed to update rules: {}", err);
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
                    menu::evebox_agent::menu(&mut context)?;
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
                println!("{}", env!("CARGO_PKG_VERSION"));
                0
            }
            Commands::Print { what } => {
                print(what)?;
                0
            }
            Commands::Systemd { command } => {
                match command {
                    SystemdCommands::Install => systemd::install()?,
                    SystemdCommands::Remove => systemd::remove(),
                }
                0
            }
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
    info!("Starting services in the foreground");

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
        let data_directory = context.data_dir().join("elastic");
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
            if !context
                .manager
                .is_running(&crate::suricata::container_name(context))
            {
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
    let _ = context
        .manager
        .stop(&crate::suricata::container_name(context), None);
    let _ = context.manager.stop(
        &crate::evebox::server::container_name(context),
        Some("SIGINT"),
    );

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

    if context
        .manager
        .container_exists(&crate::suricata::container_name(context))
    {
        info!("Stopping {}", crate::suricata::container_name(context));
        if !stop_container(context, &crate::suricata::container_name(context)) {
            ok = false;
        }
    } else {
        info!(
            "Container {} is not running",
            crate::suricata::container_name(context)
        );
    }

    if context
        .manager
        .container_exists(&crate::evebox::server::container_name(context))
    {
        info!(
            "Stopping {}",
            &crate::evebox::server::container_name(context)
        );
        if actions::stop_evebox_server(context).is_err() {
            ok = false;
        }
    } else {
        info!(
            "Container {} is not running",
            &crate::evebox::server::container_name(context)
        );
    }

    // Agent.
    if context
        .manager
        .container_exists(&crate::evebox::agent::container_name(context))
    {
        info!("Stopping {}", crate::evebox::agent::container_name(context));
        if !stop_container(context, &crate::evebox::agent::container_name(context)) {
            ok = false;
        }
    } else {
        info!(
            "Container {} is not running",
            crate::evebox::agent::container_name(context)
        );
    }

    // Stop Elasticsearch
    info!("Stoping Elasticsearch");
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
        if context
            .manager
            .is_running(&crate::suricata::container_name(context))
        {
            status.push(("info", "Suricata", "running".to_string()));
        } else {
            status.push(("warn", "Suricata", "not running".to_string()));
        }
    } else {
        status.push(("debug", "Suricata", "not enabled".to_string()));
    }

    if context.config.evebox_server.enabled {
        enabled += 1;
        if context
            .manager
            .is_running(&crate::evebox::server::container_name(context))
        {
            let url = guess_evebox_url(context);
            status.push(("info", "EveBox Server", format!("running {}", url)));
        } else {
            status.push(("warn", "EveBox Server", "not running".to_string()));
        }
    } else {
        status.push(("debug", "EveBox Server", "not enabled".to_string()));
    }

    if context.config.evebox_agent.enabled {
        enabled += 1;
        if context
            .manager
            .is_running(&crate::evebox::agent::container_name(context))
        {
            status.push(("info", "EveBox Agent", "running".to_string()));
        } else {
            status.push(("warn", "EveBox Agent", "not running".to_string()));
        }
    } else {
        status.push(("debug", "EveBox Agent", "not enabled".to_string()));
    }

    if context.config.elasticsearch.enabled {
        enabled += 1;
        if context
            .manager
            .is_running(&elastic::container_name(context))
        {
            status.push(("info", "Elasticsearch", "running".to_string()));
        } else {
            status.push(("warn", "Elasticsearch", "not running".to_string()));
        }
    } else {
        status.push(("debug", "Elasticsearch", "not enabled".to_string()));
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

fn menu_main(mut context: Context) -> Result<()> {
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
                        update(&context);
                        prompt::enter();
                    }
                    Main::Other => menu::other::menu(&context),
                    Main::Configure => menu::configure::main(&mut context)?,
                    Main::UpdateRules => {
                        if let Err(err) = actions::update_rules(&context) {
                            error!("{}", err);
                        }
                        prompt::enter();
                    }
                    Main::SuricataUpdate => menu::suricata_update::menu(&mut context)?,
                    Main::Exit => break,
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
        &crate::suricata::container_name(context),
        "--net=host",
        "--cap-add=sys_nice",
        "--cap-add=net_admin",
        "--cap-add=net_raw",
    ]);

    if detached {
        args.add("--detach");
    }

    let path = context.config_dir().join("af-packet.yaml");
    if let Err(err) = configs::write_af_packet_stub(&path) {
        error!("Failed to write af-packet stub: {err}");
    } else {
        let path = context.config_dir().join("af-packet.yaml");
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
    context
        .manager
        .quiet_rm(&crate::suricata::container_name(context));
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
            &crate::suricata::container_name(context),
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

fn build_evebox_server_command(context: &Context, daemon: bool) -> Result<process::Command> {
    let config = &context.config.evebox_server;
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--name");
    command.arg(crate::evebox::server::container_name(context));
    if context.config.evebox_server.allow_remote {
        command.arg("--publish=5636:5636");
    } else {
        command.arg("--publish=127.0.0.1:5636:5636");
    }
    if daemon {
        command.arg("--detach");
    }

    if context.config.elasticsearch.enabled {
        command.arg(format!(
            "--link={}",
            crate::elastic::container_name(context)
        ));
    }

    command.arg(format!(
        "--volume={}:/var/log/suricata",
        context.data_dir().join("suricata").join("log").display()
    ));

    let host_config_directory = context.config_dir().join("evebox").join("server");
    std::fs::create_dir_all(&host_config_directory).unwrap();
    command.arg(format!(
        "--volume={}:/config",
        host_config_directory.display()
    ));

    let host_data_directory = context.data_dir().join("evebox").join("server");
    std::fs::create_dir_all(&host_data_directory).unwrap();
    command.arg(format!("--volume={}:/data", host_data_directory.display()));

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
    } else if context.config.elasticsearch.enabled {
        // Internal Elasticsearch server.
        command.arg("--env");
        command.arg("EVEBOX_ELASTICSEARCH_INDEX=evebox");
    }

    command.arg(context.image_name(Container::EveBox));
    command.args(["evebox", "server"]);

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
    } else if context.config.elasticsearch.enabled {
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
    command.arg("/var/log/suricata/eve.json");

    Ok(command)
}

fn build_evebox_agent_command(context: &Context, detatched: bool) -> process::Command {
    let mut args = ArgBuilder::from(&[
        "run",
        "--name",
        &crate::evebox::agent::container_name(context),
    ]);
    if detatched {
        args.add("-d");
    }

    let libdir = context.data_dir().join("evebox").join("agent");
    let logdir = context.data_dir().join("suricata").join("log");

    let volumes = vec![
        format!("{}:/var/log/suricata", logdir.display()),
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
            "[year]-[month]-[day]T[hour]:[minute]:[second][offset_hour sign:mandatory][offset_minute]")
        };

        let timer = tracing_subscriber::fmt::time::LocalTime::new(format);
        tracing_subscriber::fmt()
            .with_timer(timer)
            .with_max_level(log_level)
            .init();
    }
}

fn print(what: String) -> Result<()> {
    match what.as_str() {
        "interfaces" => {
            let interfaces = evectl::system::get_interfaces()?;
            for interface in &interfaces {
                let mut addrs = interface.addr4.clone();
                addrs.extend(interface.addr6.clone());
                let addrs = addrs.join(", ");
                println!("{} {} {}", interface.name, interface.status, &addrs);
            }
        }
        "systemd" => {
            println!("{}", systemd::format_template()?);
        }
        _ => {
            error!("Unknown print target: {}", what);
        }
    }
    Ok(())
}
