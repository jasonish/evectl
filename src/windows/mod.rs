// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(windows)]
mod imp {
    use crate::prelude::*;
    use clap::{Parser, Subcommand};
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use suricatax_rules::cli as suricatax_cli;
    use suricatax_rules::paths::PathProvider;
    use suricatax_rules::sources::SourceManager;

    const NPCAP_VERSION: &str = "1.88";
    const NPCAP_INSTALLED_MARKER: &str = ".evectl-npcap-installed";
    const SURICATA_VERSION: &str = "8.0.6-1";
    const SURICATA_SYSTEM_EXE_PATHS: [&str; 2] = [
        r"C:\Program Files\Suricata\suricata.exe",
        r"C:\Program Files (x86)\Suricata\suricata.exe",
    ];
    const SURICATA_VERSION_MARKER: &str = ".evectl-suricata-version";
    const EVEBOX_VERSION: &str = "0.28.0";
    const EVEBOX_VERSION_MARKER: &str = ".evectl-evebox-version";
    const EVEBOX_URL: &str =
        "https://evebox.org/files/release/0.28.0/evebox-0.28.0-windows-x64.zip";
    const STATUS_CONTROL_C_EXIT: i32 = -1073741510;
    const ROLE_SURICATA: &str = "suricata";
    const ROLE_EVEBOX: &str = "evebox";
    const ROLE_EVEBOX_AGENT: &str = "evebox-agent";
    const EVEBOX_HOST: &str = "127.0.0.1";
    const EVEBOX_PORT: &str = "5636";
    const EVEBOX_ACCESS_URL: &str = "http://127.0.0.1:5636";
    const EVEBOX_DESKTOP_SHORTCUT_URL: &str = "http://127.0.0.1:5636";
    const START_SHORTCUT_NAME: &str = "EveCtl Start.cmd";
    const EVEBOX_SHORTCUT_NAME: &str = "EveBox.url";
    const WINDOWS_UNSUPPORTED_RULE_SUBSTRINGS: [&str; 1] = ["file.magic"];
    const SURICATA_READY_TIMEOUT: Duration = Duration::from_secs(5);
    const EVEBOX_STARTUP_GRACE_PERIOD: Duration = Duration::from_millis(750);
    const PROCESS_STOP_TIMEOUT: Duration = Duration::from_secs(5);

    static CTRL_C_RECEIVED: AtomicBool = AtomicBool::new(false);
    static CTRL_C_HANDLER_SETUP: OnceLock<Result<(), String>> = OnceLock::new();

    #[derive(Debug, Serialize, Deserialize, Clone)]
    struct RuntimeMetadata {
        pid: u32,
        role: String,
        exe_path: String,
        argv: Vec<String>,
        started_at: u64,
        stdout_path: Option<String>,
        stderr_path: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct NamedProcessInfo {
        #[serde(rename = "Id")]
        id: u32,
        #[serde(rename = "ProcessName")]
        process_name: Option<String>,
        #[serde(rename = "Path")]
        path: Option<String>,
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct UpgradePlan {
        npcap: bool,
        suricata: bool,
        evebox: bool,
    }

    impl UpgradePlan {
        fn any(self) -> bool {
            self.npcap || self.suricata || self.evebox
        }
    }

    #[derive(Debug, Default, Clone)]
    struct RestartPlan {
        suricata_running: bool,
        suricata_guid: Option<String>,
        evebox_server_running: bool,
        evebox_agent_running: bool,
    }

    impl RestartPlan {
        fn any(&self) -> bool {
            self.suricata_running || self.evebox_server_running || self.evebox_agent_running
        }
    }

    #[derive(Parser, Debug, Clone)]
    pub(crate) struct Args {
        #[command(subcommand)]
        pub(crate) command: Option<Commands>,
    }

    #[derive(Subcommand, Debug, Clone)]
    pub(crate) enum Commands {
        /// Start the Suricata and EveBox stack.
        Start {
            /// Run in the foreground, mainly for debugging
            #[arg(long, short)]
            debug: bool,

            /// Network interface GUID or name to listen on. If omitted, the saved config is used.
            #[arg(long)]
            guid: Option<String>,
        },

        /// Stop the Suricata and EveBox stack.
        Stop,

        /// Stop and start the Suricata and EveBox stack.
        Restart,

        /// Display status of each service.
        Status,

        /// Update Suricata rules.
        UpdateRules,

        /// Update EveCtl itself and the bundled Windows components.
        #[command(aliases = ["upgrade", "upgrade-suricata"])]
        Update,

        /// Display EveCtl version
        Version,

        /// Display project directories for config, rules, and logs.
        Info,

        /// Install and configure EveCtl, running the setup wizard on first use.
        Install,

        /// Stop all services and remove the EveCtl data files
        Uninstall {
            /// Also remove the configuration and Suricata rules
            #[arg(long)]
            config: bool,

            /// Remove everything: EveBox, Suricata, evectl-managed
            /// Npcap, all EveCtl files, desktop shortcuts, and the
            /// EveCtl binary
            #[arg(long)]
            all: bool,

            /// Do not prompt for confirmation
            #[arg(long, short)]
            yes: bool,
        },

        /// List network interfaces with their IP addresses and GUIDs
        ListInterfaces,

        /// Add desktop shortcuts for starting the Windows stack and opening EveBox.
        AddShortcuts,

        /// Manage evectl configuration.
        Config {
            #[command(subcommand)]
            command: ConfigCommands,
        },

        /// Manage Suricata rules and rulesets
        Rules {
            #[command(subcommand)]
            command: RulesCommands,
        },
    }

    #[derive(Subcommand, Debug, Clone)]
    pub(crate) enum ConfigCommands {
        /// Select and save the default interface name used by start.
        SetInterface,
    }

    #[derive(Subcommand, Debug, Clone)]
    pub(crate) enum RulesCommands {
        /// Update Suricata rules using built-in Windows-compatible updater
        Update {
            /// Force download even if cache is recent
            #[arg(short = 'f', long)]
            force: bool,

            /// Reduce output to warnings/errors
            #[arg(short = 'q', long)]
            quiet: bool,
        },

        /// Refresh Suricata ruleset index
        UpdateSources,

        /// Enable a Suricata ruleset (for example: et/open). If omitted, an interactive selector is shown.
        EnableRuleset {
            #[arg(value_name = "RULESET")]
            name: Option<String>,
        },

        /// Disable a Suricata ruleset
        DisableRuleset {
            #[arg(value_name = "RULESET")]
            name: String,
        },

        /// List currently enabled Suricata rulesets
        ListEnabledRulesets,
    }

    impl Args {
        pub(crate) fn from_command(command: Option<Commands>) -> Self {
            Self { command }
        }
    }

    pub(crate) fn main(args: Args) -> Result<()> {
        match args.command {
            Some(Commands::Start { debug, guid }) => start_stack(debug, guid),
            Some(Commands::Stop) => stop_stack(),
            Some(Commands::Restart) => restart_stack(),
            Some(Commands::Status) => {
                log_status(windows_status(&load_evectl_config()?)?);
                Ok(())
            }
            Some(Commands::UpdateRules) => update_rules(false, false),
            Some(Commands::Update) => upgrade_windows_components(),
            Some(Commands::Version) => {
                println!("{}", env!("EVECTL_VERSION"));
                Ok(())
            }
            Some(Commands::Info) => project_info(),
            Some(Commands::Install) => install(),
            Some(Commands::Uninstall { config, all, yes }) => uninstall(config, all, yes),
            Some(Commands::ListInterfaces) => list_interfaces(),
            Some(Commands::AddShortcuts) => add_shortcuts(),
            Some(Commands::Config { command }) => match command {
                ConfigCommands::SetInterface => config_set_interface(),
            },
            Some(Commands::Rules { command }) => match command {
                RulesCommands::Update { force, quiet } => update_rules(force, quiet),
                RulesCommands::UpdateSources => update_sources(),
                RulesCommands::EnableRuleset { name } => enable_ruleset(name.as_deref()),
                RulesCommands::DisableRuleset { name } => disable_ruleset(&name),
                RulesCommands::ListEnabledRulesets => list_enabled_rulesets(),
            },
            None => menu_main(),
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum MainMenuOption {
        Refresh,
        Restart,
        Stop,
        Start,
        Install,
        UpdateRules,
        ManageRules,
        Update,
        Configure,
        Other,
        Exit,
    }

    #[derive(Debug, Clone, Copy)]
    enum ConfigureMenuOption {
        Suricata,
        EveBoxAgent,
        EveBoxServer,
        Shortcuts,
        Return,
    }

    #[derive(Debug, Clone, Copy)]
    enum ConfigureSuricataMenuOption {
        Toggle,
        Interface,
        SensorName,
        Bpf,
        Return,
    }

    #[derive(Debug, Clone, Copy)]
    enum ConfigureAgentMenuOption {
        Toggle,
        Server,
        Return,
    }

    #[derive(Debug, Clone, Copy)]
    enum ConfigureServerMenuOption {
        Toggle,
        Return,
    }

    #[derive(Debug, Clone, Copy)]
    enum RulesMenuOption {
        Enable,
        Disable,
        Update,
        UpdateSources,
        ListEnabled,
        Return,
    }

    #[derive(Debug, Clone, Copy)]
    enum OtherMenuOption {
        Install,
        Uninstall,
        Interfaces,
        Info,
        Return,
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct WindowsStatus {
        suricata_enabled: bool,
        suricata_installed: bool,
        suricata_running: bool,
        evebox_installed: bool,
        evebox_server_enabled: bool,
        evebox_server_running: bool,
        evebox_agent_enabled: bool,
        evebox_agent_running: bool,
    }

    impl WindowsStatus {
        fn any_enabled(self) -> bool {
            self.suricata_enabled || self.evebox_server_enabled || self.evebox_agent_enabled
        }

        fn any_running(self) -> bool {
            self.suricata_running || self.evebox_server_running || self.evebox_agent_running
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

    fn windows_status(config: &crate::config::Config) -> Result<WindowsStatus> {
        Ok(WindowsStatus {
            suricata_enabled: config.suricata.enabled,
            suricata_installed: find_suricata_executable().is_some(),
            suricata_running: managed_process_is_running(ROLE_SURICATA)?,
            evebox_installed: find_evebox_exe(&get_evebox_install_dir()?)?.is_some(),
            evebox_server_enabled: config.evebox_server.enabled,
            evebox_server_running: managed_process_is_running(ROLE_EVEBOX)?,
            evebox_agent_enabled: config.evebox_agent.enabled,
            evebox_agent_running: managed_process_is_running(ROLE_EVEBOX_AGENT)?,
        })
    }

    fn log_status(status: WindowsStatus) {
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
                info!("{:-13}: running {}", "EveBox Server", EVEBOX_ACCESS_URL);
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

    fn menu_main() -> Result<()> {
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

        let mut original_config = config.clone();

        loop {
            // Save a changed configuration and offer a restart, and keep
            // offering until a restart happens.
            if config != original_config {
                ensure_dir(&get_evectl_data_dir()?)?;
                config.save()?;

                if let Ok(Some(true)) = inquire::Confirm::new("Configuration has changed, restart?")
                    .with_default(true)
                    .prompt_skippable()
                {
                    run_menu_action("Failed to restart Windows stack", restart_stack);
                    original_config = config.clone();
                }
            }

            crate::term::title("EveCtl: Main Menu");

            let status = match windows_status(&config) {
                Ok(status) => status,
                Err(err) => {
                    error!("Failed to determine Windows service status: {}", err);
                    WindowsStatus::default()
                }
            };
            log_status(status);
            println!();

            if original_config != config {
                warn!("Configuration has changed, restart required");
            }

            let mut selections = crate::prompt::Selections::with_index();
            selections.push(MainMenuOption::Refresh, "Refresh Status");
            if status.any_running() {
                selections.push(MainMenuOption::Restart, "Restart");
                selections.push(MainMenuOption::Stop, "Stop");
            } else if status.ready_to_start() {
                selections.push(MainMenuOption::Start, "Start");
            } else {
                selections.push(MainMenuOption::Install, "Install");
            }
            if status.suricata_enabled {
                selections.push(MainMenuOption::UpdateRules, "Update Rules");
                selections.push(MainMenuOption::ManageRules, "Manage Rules");
            }
            selections.push(MainMenuOption::Update, "Update");
            selections.push(MainMenuOption::Configure, "Configure");
            selections.push(MainMenuOption::Other, "Other");
            selections.push(MainMenuOption::Exit, "Exit");

            let selection = match inquire::Select::new("Select a menu option", selections.to_vec())
                .with_page_size(12)
                .prompt()
            {
                Ok(selection) => selection,
                Err(_) => break,
            };

            match selection.tag {
                MainMenuOption::Refresh => {}
                MainMenuOption::Restart => {
                    run_menu_action("Failed to restart Windows stack", restart_stack);
                    original_config = config.clone();
                }
                MainMenuOption::Stop => {
                    run_menu_action("Failed to stop Windows stack", stop_stack);
                }
                MainMenuOption::Start => {
                    run_menu_action("Failed to start Windows stack", || start_stack(false, None));
                }
                MainMenuOption::Install => {
                    run_menu_action_with_pause("Installation failed", || install_with(&mut config));
                    // A wizard run saves its own configuration; don't
                    // treat it as a pending change needing a restart.
                    original_config = config.clone();
                }
                MainMenuOption::UpdateRules => {
                    run_menu_action_with_pause("Failed to update rules", || {
                        update_rules(false, false)
                    });
                }
                MainMenuOption::ManageRules => rules_menu()?,
                MainMenuOption::Update => {
                    run_menu_action_with_pause(
                        "Failed to update Windows components",
                        upgrade_windows_components,
                    );
                }
                MainMenuOption::Configure => configure_menu(&mut config)?,
                MainMenuOption::Other => other_menu(&mut config)?,
                MainMenuOption::Exit => break,
            }
        }

        Ok(())
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

    #[derive(Debug, Clone)]
    enum InstallType {
        Standalone,
        Agent,
        Server,
        Custom,
        Help,
    }

    /// First-run setup wizard, mirroring the Linux wizard: choose an
    /// installation type, answer all questions up front, then install.
    fn wizard(config: &mut crate::config::Config) -> Result<()> {
        let mut selections = crate::prompt::Selections::new();
        selections.push(
            InstallType::Standalone,
            "Standalone: Suricata + EveBox Server",
        );
        selections.push(InstallType::Agent, "Agent:      Suricata + EveBox Agent");
        selections.push(InstallType::Server, "Server:     EveBox server only");
        selections.push(
            InstallType::Custom,
            "Custom:     Exit the wizard and perform manual configuration",
        );
        selections.push(InstallType::Help, "Help:       Show help");

        let install_type;
        loop {
            let selection = match inquire::Select::new(
                "What type of installation would you like to initialize?",
                selections.to_vec(),
            )
            .prompt()
            {
                Ok(selection) => selection,
                // Treat ESC like Custom: manual configuration.
                Err(_) => return Ok(()),
            };

            install_type = match selection.tag {
                InstallType::Custom => return Ok(()),
                InstallType::Help => {
                    install_type_help();
                    continue;
                }
                other => other,
            };

            break;
        }

        let has_suricata = matches!(install_type, InstallType::Standalone | InstallType::Agent);
        let has_server = matches!(install_type, InstallType::Standalone | InstallType::Server);

        // Ask all questions up front, before any downloads.

        if has_suricata {
            let interface = prompt_for_interface(
                "Suricata: What network interface should Suricata listen on?",
            )?;
            config.suricata.enabled = true;
            config.suricata.interfaces = vec![interface.name];
        }

        if let InstallType::Agent = install_type {
            loop {
                if let Some((url, disable_certificate_validation)) =
                    crate::menu::evebox_agent::prompt_for_server_url(config)?
                {
                    config.evebox_agent.enabled = true;
                    config.evebox_agent.server = url;
                    config.evebox_agent.disable_certificate_validation =
                        disable_certificate_validation;
                    break;
                }
            }
        }

        if has_server {
            // The Windows EveBox server currently runs with fixed options:
            // SQLite datastore, localhost only, no TLS, no authentication.
            config.evebox_server.enabled = true;
        }

        if !inquire::Confirm::new("Would you like to proceed with this configuration?")
            .with_default(true)
            .prompt()?
        {
            bail!("Aborting configuration wizard. Bye!");
        }

        // Questions done, on to the installs. The configuration is not
        // saved until installation completes so a failure here results
        // in the wizard being run again on next start.

        install_configured_components(config)?;

        if has_suricata {
            info!("Updating Suricata rules...");
            update_rules(false, false)?;
        }

        ensure_dir(&get_evectl_data_dir()?)?;
        config.save()?;

        Ok(())
    }

    fn install_type_help() {
        let msg = format!(
            "
{:11      } Suricata and EveBox all-in-one. Suitable for single
            host deployments. Events are stored in SQLite.

{:11      } Suricata and EveBox Agent. Useful if you already
            have an EveBox server and need to deploy another
            Suricata instance.

{:11      } EveBox server only. Events are stored in SQLite.

{:11      } Exit the wizard and perform manual configuration.
",
            "Standalone:".cyan(),
            "Agent:".blue(),
            "Server:".green(),
            "Custom:".yellow()
        );
        println!("{}", msg);
        crate::prompt::enter();
    }

    fn configure_menu(config: &mut crate::config::Config) -> Result<()> {
        loop {
            crate::term::clear();

            let interface = config
                .suricata
                .interfaces
                .first()
                .map(String::from)
                .unwrap_or_default();

            let mut selections = crate::prompt::Selections::with_index();
            selections.push(
                ConfigureMenuOption::Suricata,
                format!(
                    "Configure Suricata [enabled={}, interface={}]",
                    config.suricata.enabled,
                    if interface.is_empty() {
                        "None"
                    } else {
                        &interface
                    }
                ),
            );
            selections.push(
                ConfigureMenuOption::EveBoxAgent,
                format!(
                    "Configure EveBox Agent [enabled={}]",
                    config.evebox_agent.enabled
                ),
            );
            selections.push(
                ConfigureMenuOption::EveBoxServer,
                format!(
                    "Configure EveBox Server [enabled={}]",
                    config.evebox_server.enabled
                ),
            );
            selections.push(ConfigureMenuOption::Shortcuts, "Add Desktop Shortcuts");
            selections.push(ConfigureMenuOption::Return, "Return");

            let selection =
                match inquire::Select::new("EveCtl: Configure", selections.to_vec()).prompt() {
                    Ok(selection) => selection,
                    Err(_) => break,
                };

            match selection.tag {
                ConfigureMenuOption::Suricata => configure_suricata_menu(config)?,
                ConfigureMenuOption::EveBoxAgent => configure_evebox_agent_menu(config)?,
                ConfigureMenuOption::EveBoxServer => configure_evebox_server_menu(config)?,
                ConfigureMenuOption::Shortcuts => {
                    run_menu_action_with_pause("Failed to add desktop shortcuts", add_shortcuts)
                }
                ConfigureMenuOption::Return => break,
            }
        }

        Ok(())
    }

    fn configure_suricata_menu(config: &mut crate::config::Config) -> Result<()> {
        loop {
            crate::term::clear();

            let mut selections = crate::prompt::Selections::new();
            if config.suricata.enabled {
                selections.push(ConfigureSuricataMenuOption::Toggle, "Disable Suricata");
            } else {
                selections.push(ConfigureSuricataMenuOption::Toggle, "Enable Suricata");
            }

            let interface_label = match config.suricata.interfaces.first() {
                Some(interface) => format!("Select Interface (current: {})", interface),
                None => "Select Interface".to_string(),
            };
            selections.push(ConfigureSuricataMenuOption::Interface, interface_label);

            selections.push(ConfigureSuricataMenuOption::SensorName, {
                if let Some(sensor_name) = &config.suricata.sensor_name {
                    format!("Sensor Name (current: {})", sensor_name)
                } else {
                    "Sensor Name (current: none)".to_string()
                }
            });

            let current_bpf = if let Some(bpf) = &config.suricata.bpf {
                format!(" (current: \"{}\")", bpf)
            } else {
                " (current: none)".to_string()
            };
            selections.push(
                ConfigureSuricataMenuOption::Bpf,
                format!("BPF filter{}", current_bpf),
            );

            selections.push(ConfigureSuricataMenuOption::Return, "Return");

            let selection =
                match inquire::Select::new("EveCtl: Configure Suricata", selections.to_vec())
                    .prompt()
                {
                    Ok(selection) => selection,
                    Err(_) => break,
                };

            match selection.tag {
                ConfigureSuricataMenuOption::Toggle => {
                    config.suricata.enabled = !config.suricata.enabled;
                    if config.suricata.enabled && config.suricata.interfaces.is_empty() {
                        select_interface_into(config);
                    }
                }
                ConfigureSuricataMenuOption::Interface => select_interface_into(config),
                ConfigureSuricataMenuOption::SensorName => {
                    crate::menu::suricata::set_sensor_name(config)
                }
                ConfigureSuricataMenuOption::Bpf => crate::menu::suricata::set_bpf_filter(config),
                ConfigureSuricataMenuOption::Return => break,
            }
        }

        Ok(())
    }

    fn select_interface_into(config: &mut crate::config::Config) {
        match prompt_for_interface("Select Interface") {
            Ok(interface) => config.suricata.interfaces = vec![interface.name],
            Err(err) if prompt_was_cancelled(&err) => {}
            Err(err) => {
                error!("Failed to select a network interface: {}", err);
                crate::prompt::enter();
            }
        }
    }

    fn configure_evebox_agent_menu(config: &mut crate::config::Config) -> Result<()> {
        loop {
            crate::term::clear();

            let mut selections = crate::prompt::Selections::new();
            if config.evebox_agent.enabled {
                selections.push(ConfigureAgentMenuOption::Toggle, "Disable Agent [enabled]");
            } else {
                selections.push(ConfigureAgentMenuOption::Toggle, "Enable Agent [disabled]");
            }
            selections.push(
                ConfigureAgentMenuOption::Server,
                format!("EveBox Server URL [{}]", config.evebox_agent.server),
            );
            selections.push(ConfigureAgentMenuOption::Return, "Return");

            let selection =
                match inquire::Select::new("EveCtl: Configure EveBox Agent", selections.to_vec())
                    .prompt_skippable()?
                {
                    Some(selection) => selection,
                    None => break,
                };

            match selection.tag {
                ConfigureAgentMenuOption::Toggle => {
                    config.evebox_agent.enabled = !config.evebox_agent.enabled;
                    if config.evebox_agent.enabled && config.evebox_agent.server.is_empty() {
                        crate::menu::evebox_agent::set_server(config)?;
                    }
                }
                ConfigureAgentMenuOption::Server => crate::menu::evebox_agent::set_server(config)?,
                ConfigureAgentMenuOption::Return => break,
            }
        }

        Ok(())
    }

    fn configure_evebox_server_menu(config: &mut crate::config::Config) -> Result<()> {
        loop {
            crate::term::clear();

            let mut selections = crate::prompt::Selections::with_index();
            if config.evebox_server.enabled {
                selections.push(
                    ConfigureServerMenuOption::Toggle,
                    "Disable EveBox Server [enabled]",
                );
            } else {
                selections.push(
                    ConfigureServerMenuOption::Toggle,
                    "Enable EveBox Server [disabled]",
                );
            }
            selections.push(ConfigureServerMenuOption::Return, "Return");

            let selection =
                match inquire::Select::new("EveCtl: Configure EveBox Server", selections.to_vec())
                    .prompt()
                {
                    Ok(selection) => selection,
                    Err(_) => break,
                };

            match selection.tag {
                ConfigureServerMenuOption::Toggle => {
                    config.evebox_server.enabled = !config.evebox_server.enabled;
                }
                ConfigureServerMenuOption::Return => break,
            }
        }

        Ok(())
    }

    fn rules_menu() -> Result<()> {
        loop {
            crate::term::title("EveCtl: Manage Rules");

            let mut selections = crate::prompt::Selections::with_index();
            selections.push(RulesMenuOption::Enable, "Enable a Ruleset");
            selections.push(RulesMenuOption::Disable, "Disable a Ruleset");
            selections.push(RulesMenuOption::Update, "Update Rules");
            selections.push(RulesMenuOption::UpdateSources, "Update Rule Sources");
            selections.push(RulesMenuOption::ListEnabled, "List Enabled Rulesets");
            selections.push(RulesMenuOption::Return, "Return");

            let selection = match inquire::Select::new("Select menu option", selections.to_vec())
                .prompt_skippable()?
            {
                Some(selection) => selection,
                None => break,
            };

            match selection.tag {
                RulesMenuOption::Enable => {
                    run_menu_action("Failed to enable ruleset", enable_ruleset_interactive)
                }
                RulesMenuOption::Disable => {
                    run_menu_action("Failed to disable ruleset", disable_ruleset_interactive)
                }
                RulesMenuOption::Update => {
                    run_menu_action_with_pause("Failed to update rules", || {
                        update_rules(false, false)
                    })
                }
                RulesMenuOption::UpdateSources => {
                    run_menu_action_with_pause("Failed to update rule sources", update_sources)
                }
                RulesMenuOption::ListEnabled => run_menu_action_with_pause(
                    "Failed to list enabled rulesets",
                    list_enabled_rulesets,
                ),
                RulesMenuOption::Return => break,
            }
        }

        Ok(())
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
                    let uninstall = inquire::Confirm::new(
                        "Uninstall EveBox, Suricata, and evectl-managed Npcap?",
                    )
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

    fn run_menu_action(message: &str, action: impl FnOnce() -> Result<()>) {
        if let Err(err) = action() {
            error!("{}: {}", message, err);
            crate::prompt::enter();
        }
    }

    fn run_menu_action_with_pause(message: &str, action: impl FnOnce() -> Result<()>) {
        if let Err(err) = action() {
            error!("{}: {}", message, err);
        }
        crate::prompt::enter();
    }
    struct EvectlWindowsPaths {
        sources_dir: std::path::PathBuf,
        cache_dir: std::path::PathBuf,
        rules_dir: std::path::PathBuf,
    }

    impl PathProvider for EvectlWindowsPaths {
        fn sources_dir(&self) -> std::path::PathBuf {
            self.sources_dir.clone()
        }

        fn cache_dir(&self) -> std::path::PathBuf {
            self.cache_dir.clone()
        }

        fn rules_dir(&self) -> std::path::PathBuf {
            self.rules_dir.clone()
        }
    }

    #[cfg(windows)]
    fn get_suricatax_paths() -> Result<EvectlWindowsPaths> {
        let lib_dir = get_suricata_data_dir()?.join("lib");
        Ok(EvectlWindowsPaths {
            sources_dir: lib_dir.join("update").join("sources"),
            cache_dir: lib_dir.join("update").join("cache"),
            rules_dir: lib_dir.join("rules"),
        })
    }

    #[cfg(windows)]
    fn with_path_provider<T>(f: impl FnOnce(&dyn PathProvider) -> Result<T>) -> Result<T> {
        let paths = get_suricatax_paths()?;
        f(&paths)
    }

    #[cfg(windows)]
    fn update_rules(force: bool, quiet: bool) -> Result<()> {
        let suricata_version = detect_suricata_version_for_rules_update();
        let disable_substrings = WINDOWS_UNSUPPORTED_RULE_SUBSTRINGS
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();

        if let Some(version) = &suricata_version {
            info!("Selecting rules for Suricata version {}", version);
        } else {
            warn!(
                "Could not determine Suricata version for rules update; using suricatax-rules default"
            );
        }

        if !disable_substrings.is_empty() {
            info!(
                "Disabling rules containing unsupported Suricata for Windows keywords: {}",
                disable_substrings.join(", ")
            );
        }

        // The updater always rewrites its output, so compare a digest
        // of the rules directory before and after to tell whether the
        // rules actually changed.
        let rules_dir = get_suricatax_paths()?.rules_dir;
        let before = rules_digest(&rules_dir)?;

        with_path_provider(|paths| {
            suricatax_cli::update_rules_with_options(
                paths,
                force,
                quiet,
                suricata_version.as_deref(),
                &[],
                &disable_substrings,
            )
        })?;

        if rules_digest(&rules_dir)? == before {
            info!("Rules unchanged, Suricata does not need to be restarted");
            return Ok(());
        }

        restart_suricata_for_rules()
    }

    /// A digest of every file under the rules directory (the rules
    /// file and any dataset files), or None if it doesn't exist yet.
    #[cfg(windows)]
    fn rules_digest(rules_dir: &Path) -> Result<Option<String>> {
        use sha2::{Digest, Sha256};

        fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
            for entry in std::fs::read_dir(dir)
                .with_context(|| format!("Failed to read {}", dir.display()))?
            {
                let path = entry?.path();
                if path.is_dir() {
                    collect(&path, files)?;
                } else {
                    files.push(path);
                }
            }
            Ok(())
        }

        if !rules_dir.exists() {
            return Ok(None);
        }

        let mut files = vec![];
        collect(rules_dir, &mut files)?;
        files.sort();

        let mut hash = Sha256::new();
        for path in files {
            let relative = path.strip_prefix(rules_dir).unwrap_or(&path);
            hash.update(relative.to_string_lossy().as_bytes());
            hash.update([0]);
            hash.update(
                std::fs::read(&path)
                    .with_context(|| format!("Failed to read {}", path.display()))?,
            );
            hash.update([0]);
        }
        Ok(Some(
            hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        ))
    }

    /// Suricata on Windows can't reload rules in place, so restart it,
    /// if running, to load the updated rules.
    #[cfg(windows)]
    fn restart_suricata_for_rules() -> Result<()> {
        let plan = capture_restart_plan()?;
        if !plan.suricata_running {
            return Ok(());
        }
        let guid = plan.suricata_guid.as_deref().ok_or_else(|| {
            anyhow!("Failed to determine the interface GUID used by the running Suricata process")
        })?;

        info!("Restarting Suricata to load the updated rules");
        let result = (|| {
            stop_suricata_managed()?;
            let suricata = start_suricata_background(guid)?;
            wait_for_suricata_readiness(&suricata)
        })();
        result.map_err(|err| anyhow!("Rules updated, but restarting Suricata failed: {}", err))
    }

    #[cfg(windows)]
    fn detect_suricata_version_for_rules_update() -> Option<String> {
        if let Some(version) = get_suricata_runtime_version() {
            return Some(version);
        }

        match get_suricata_installed_version() {
            Ok(Some(version)) => normalize_suricata_version(&version)
                .or_else(|| normalize_suricata_version(suricata_version_for_comparison())),
            Ok(None) => normalize_suricata_version(suricata_version_for_comparison()),
            Err(err) => {
                warn!(
                    "Failed to determine installed Suricata version for rules update: {}",
                    err
                );
                normalize_suricata_version(suricata_version_for_comparison())
            }
        }
    }

    #[cfg(windows)]
    fn get_suricata_runtime_version() -> Option<String> {
        use std::process::Command;

        let suricata_path = find_suricata_executable()?;
        let output = Command::new(&suricata_path).arg("-V").output().ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(version) = parse_suricata_version_from_text(&stdout) {
            return Some(version);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        parse_suricata_version_from_text(&stderr)
    }

    #[cfg(windows)]
    fn parse_suricata_version_from_text(text: &str) -> Option<String> {
        use std::sync::LazyLock;

        static VERSION_HINT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r"(?i)\b(?:suricata\s+)?version\s+([0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?)\b",
            )
            .expect("hardcoded regex is valid")
        });
        static SEMVER_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"\b([0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?)\b")
                .expect("hardcoded regex is valid")
        });

        if let Some(caps) = VERSION_HINT_RE.captures(text)
            && let Some(candidate) = caps.get(1)
            && let Some(version) = normalize_suricata_version(candidate.as_str())
        {
            return Some(version);
        }

        for caps in SEMVER_RE.captures_iter(text) {
            if let Some(candidate) = caps.get(1)
                && let Some(version) = normalize_suricata_version(candidate.as_str())
            {
                return Some(version);
            }
        }

        None
    }

    #[cfg(windows)]
    fn normalize_suricata_version(version: &str) -> Option<String> {
        let candidate = version
            .trim()
            .trim_matches(['"', '\''])
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split('-')
            .next()
            .unwrap_or("")
            .trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');

        if parse_version_parts(candidate).is_some() {
            Some(candidate.to_string())
        } else {
            None
        }
    }

    #[cfg(windows)]
    fn update_sources() -> Result<()> {
        with_path_provider(suricatax_cli::update_sources)
    }

    #[cfg(windows)]
    fn enable_ruleset(name: Option<&str>) -> Result<()> {
        match name {
            Some(name) => with_path_provider(|paths| suricatax_cli::enable_ruleset(paths, name)),
            None => enable_ruleset_interactive(),
        }
    }

    #[cfg(windows)]
    fn enable_ruleset_interactive() -> Result<()> {
        let paths = get_suricatax_paths()?;
        let index = SourceManager::new(&paths).get_or_download_index()?;
        let enabled = suricatax_cli::enabled_rulesets(&paths)?;

        let mut sources: Vec<_> = index.sources.iter().collect();
        sources.sort_by(|a, b| a.0.cmp(b.0));

        let mut selections = crate::prompt::Selections::new();
        for (id, source) in sources {
            if source.obsolete.is_some() || source.parameters.is_some() || enabled.contains(id) {
                continue;
            }
            selections.push(
                id.clone(),
                format!("{}: {}", id, source.summary.green().italic()),
            );
        }

        if let Ok(selection) = inquire::Select::new(
            "Choose a ruleset to enable or ESC to exit",
            selections.to_vec(),
        )
        .with_page_size(16)
        .prompt()
        {
            enable_ruleset(Some(&selection.tag))?;

            if crate::prompt::confirm(
                "Would you like to update your rules now?",
                Some("A rule update is required to make the new ruleset active"),
            ) && let Err(err) = update_rules(false, false)
            {
                error!("Failed to update rules: {}", err);
            }

            crate::prompt::enter();
        }

        Ok(())
    }

    #[cfg(windows)]
    fn disable_ruleset(name: &str) -> Result<()> {
        with_path_provider(|paths| suricatax_cli::disable_ruleset(paths, name))
    }

    #[cfg(windows)]
    fn disable_ruleset_interactive() -> Result<()> {
        let paths = get_suricatax_paths()?;
        let enabled = suricatax_cli::enabled_rulesets(&paths)?;
        if enabled.is_empty() {
            crate::prompt::enter_with_prefix("No rulesets enabled");
            return Ok(());
        }

        // Summaries come from the local ruleset index when available,
        // falling back to the bare ruleset name.
        let index = SourceManager::new(&paths)
            .read_local_index()
            .unwrap_or(None);

        let mut selections = crate::prompt::Selections::new();
        for id in &enabled {
            let label = match index.as_ref().and_then(|index| index.sources.get(id)) {
                Some(source) => format!("{}: {}", id, source.summary.green().italic()),
                None => id.clone(),
            };
            selections.push(id.clone(), label);
        }

        if let Ok(selection) = inquire::Select::new(
            "Choose a ruleset to DISABLE or ESC to exit",
            selections.to_vec(),
        )
        .with_page_size(16)
        .prompt()
        {
            disable_ruleset(&selection.tag)?;

            if crate::prompt::confirm(
                "Would you like to update your rules now?",
                Some("A rule update is required to complete disabling this ruleset"),
            ) && let Err(err) = update_rules(false, false)
            {
                error!("Failed to update rules: {}", err);
            }

            crate::prompt::enter();
        }

        Ok(())
    }

    #[cfg(windows)]
    fn list_enabled_rulesets() -> Result<()> {
        let rulesets = with_path_provider(suricatax_cli::enabled_rulesets)?;

        if rulesets.is_empty() {
            println!("No Suricata rulesets enabled");
            return Ok(());
        }

        println!("Enabled Suricata rulesets:");
        for ruleset in rulesets {
            println!("- {}", ruleset);
        }

        Ok(())
    }

    #[cfg(windows)]
    fn write_suricata_rules_include_stub() -> Result<std::path::PathBuf> {
        let paths = get_suricatax_paths()?;
        std::fs::create_dir_all(&paths.rules_dir).context(format!(
            "Failed to create Suricata rules directory {}",
            paths.rules_dir.display()
        ))?;

        let run_dir = get_suricata_run_dir()?;
        std::fs::create_dir_all(&run_dir).context(format!(
            "Failed to create Suricata runtime directory {}",
            run_dir.display()
        ))?;

        let include_path = run_dir.join("rules-include.yaml");
        let rules_dir = paths.rules_dir.to_string_lossy().replace('\'', "''");

        let stub = format!(
            "%YAML 1.1\n---\ndefault-rule-path: '{}'\nrule-files:\n  - suricata.rules\n",
            rules_dir
        );

        std::fs::write(&include_path, stub).context(format!(
            "Failed to write Suricata rules include file {}",
            include_path.display()
        ))?;

        Ok(include_path)
    }

    #[cfg(windows)]
    fn ensure_dir(path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)
            .context(format!("Failed to create directory {}", path.display()))
    }

    #[cfg(windows)]
    fn write_pid(path: &Path, pid: u32) -> Result<()> {
        std::fs::write(path, format!("{pid}\n"))
            .context(format!("Failed to write PID file {}", path.display()))
    }

    #[cfg(windows)]
    fn read_pid(path: &Path) -> Result<Option<u32>> {
        if !path.exists() {
            return Ok(None);
        }

        let raw = std::fs::read_to_string(path)
            .context(format!("Failed to read PID file {}", path.display()))?;
        let pid = raw
            .trim()
            .parse::<u32>()
            .context(format!("Failed to parse PID file {}", path.display()))?;
        Ok(Some(pid))
    }

    #[cfg(windows)]
    fn remove_file_if_exists(path: &Path) -> Result<()> {
        if path.exists() {
            std::fs::remove_file(path)
                .context(format!("Failed to remove file {}", path.display()))?;
        }
        Ok(())
    }

    #[cfg(windows)]
    fn write_runtime_metadata(path: &Path, metadata: &RuntimeMetadata) -> Result<()> {
        let contents = serde_json::to_string_pretty(metadata)?;
        std::fs::write(path, contents).context(format!(
            "Failed to write runtime metadata {}",
            path.display()
        ))
    }

    #[cfg(windows)]
    fn read_runtime_metadata(path: &Path) -> Result<Option<RuntimeMetadata>> {
        if !path.exists() {
            return Ok(None);
        }

        let contents = std::fs::read_to_string(path).context(format!(
            "Failed to read runtime metadata {}",
            path.display()
        ))?;
        let metadata = serde_json::from_str(&contents).context(format!(
            "Failed to parse runtime metadata {}",
            path.display()
        ))?;
        Ok(Some(metadata))
    }

    #[cfg(windows)]
    fn normalize_path_for_compare(path: &Path) -> String {
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    #[cfg(windows)]
    fn command_argv(command: &Command) -> Vec<String> {
        let mut argv = vec![command.get_program().to_string_lossy().to_string()];
        argv.extend(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string()),
        );
        argv
    }

    #[cfg(windows)]
    fn build_runtime_metadata(
        role: &str,
        command: &Command,
        pid: u32,
        stdout_path: Option<&Path>,
        stderr_path: Option<&Path>,
    ) -> Result<RuntimeMetadata> {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System clock is before UNIX_EPOCH")?
            .as_secs();

        Ok(RuntimeMetadata {
            pid,
            role: role.to_string(),
            exe_path: command.get_program().to_string_lossy().to_string(),
            argv: command_argv(command),
            started_at,
            stdout_path: stdout_path.map(|path| path.to_string_lossy().to_string()),
            stderr_path: stderr_path.map(|path| path.to_string_lossy().to_string()),
        })
    }

    #[cfg(windows)]
    fn powershell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    #[cfg(windows)]
    fn spawn_detached(command: &Command) -> Result<u32> {
        let program = powershell_quote(&command.get_program().to_string_lossy());
        let working_dir = command
            .get_current_dir()
            .map(|path| powershell_quote(&path.to_string_lossy()))
            .unwrap_or_else(|| "'.'".to_string());
        let argument_list = command
            .get_args()
            .map(|arg| powershell_quote(&arg.to_string_lossy()))
            .collect::<Vec<_>>()
            .join(", ");

        let script = format!(
            "$argList = @({argument_list}); \
             $p = Start-Process -FilePath {program} -WorkingDirectory {working_dir} \
             -ArgumentList $argList -WindowStyle Hidden -PassThru; \
             Write-Output $p.Id"
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .context("Failed to spawn detached process")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to spawn detached process: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .trim()
            .parse::<u32>()
            .context("Failed to parse detached process PID")
    }

    #[cfg(windows)]
    fn count_named_processes(process_name: &str) -> Result<usize> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = @(Get-Process -Name '{}' -ErrorAction SilentlyContinue); Write-Output $p.Count",
                    process_name.replace('\'', "''")
                ),
            ])
            .output()
            .context("Failed to query process list")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to query process list: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .trim()
            .parse::<usize>()
            .context("Failed to parse process count")
    }

    #[cfg(windows)]
    fn list_named_processes(process_name: &str) -> Result<Vec<NamedProcessInfo>> {
        let script = format!(
            "$procs = @(Get-Process -Name '{}' -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path); ConvertTo-Json -InputObject @($procs) -Compress",
            process_name.replace('\'', "''")
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .context("Failed to query process details")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to query process details: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stdout = stdout.trim();
        if stdout.is_empty() {
            return Ok(vec![]);
        }

        serde_json::from_str(stdout).context("Failed to parse process details")
    }

    #[cfg(windows)]
    fn is_pid_running(pid: u32) -> bool {
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($null -ne $p) {{ exit 0 }} else {{ exit 1 }}",
                    pid
                ),
            ])
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(windows)]
    fn get_process_exe_path(pid: u32) -> Result<Option<PathBuf>> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; if ($null -ne $p -and $p.Path) {{ Write-Output $p.Path }}",
                    pid
                ),
            ])
            .output()
            .context("Failed to inspect process executable path")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "Failed to inspect process executable path: {}",
                stderr.trim()
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout.trim();
        if path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(PathBuf::from(path)))
        }
    }

    #[cfg(windows)]
    fn process_matches_exe(pid: u32, exe_path: &Path) -> Result<bool> {
        let running_path = match get_process_exe_path(pid)? {
            Some(path) => path,
            None => return Ok(false),
        };

        Ok(normalize_path_for_compare(&running_path) == normalize_path_for_compare(exe_path))
    }

    #[cfg(windows)]
    fn path_is_same_or_descendant(path: &Path, dir: &Path) -> bool {
        let path = normalize_path_for_compare(path);
        let dir = normalize_path_for_compare(dir);

        if path == dir {
            return true;
        }

        let mut prefix = dir;
        if !prefix.ends_with('\\') {
            prefix.push('\\');
        }

        path.starts_with(&prefix)
    }

    #[cfg(windows)]
    fn process_matches_dir(
        process: &NamedProcessInfo,
        dir: &Path,
        exact_exe_path: Option<&Path>,
    ) -> Result<bool> {
        if let Some(path) = process.path.as_deref() {
            return Ok(path_is_same_or_descendant(Path::new(path), dir));
        }

        if let Some(exe_path) = exact_exe_path {
            return process_matches_exe(process.id, exe_path);
        }

        Ok(false)
    }

    #[cfg(windows)]
    fn format_process_info(process: &NamedProcessInfo) -> String {
        match process.path.as_deref() {
            Some(path) if !path.is_empty() => format!(
                "PID {} ({}) [{}]",
                process.id,
                process.process_name.as_deref().unwrap_or("unknown"),
                path
            ),
            _ => format!(
                "PID {} ({})",
                process.id,
                process.process_name.as_deref().unwrap_or("unknown")
            ),
        }
    }

    #[cfg(windows)]
    fn log_processes_in_dir(
        process_name: &str,
        dir: &Path,
        exact_exe_path: Option<&Path>,
    ) -> Result<()> {
        let mut matches = vec![];

        for process in list_named_processes(process_name)? {
            if process_matches_dir(&process, dir, exact_exe_path)? {
                matches.push(format_process_info(&process));
            }
        }

        if matches.is_empty() {
            info!(
                "No {} processes were found running from {}",
                process_name,
                dir.display()
            );
        } else {
            warn!(
                "Detected {} process(es) running from {}:\n- {}",
                process_name,
                dir.display(),
                matches.join("\n- ")
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn stop_named_processes_in_dir(
        process_name: &str,
        dir: &Path,
        exact_exe_path: Option<&Path>,
    ) -> Result<()> {
        let mut matched_pids = vec![];

        for process in list_named_processes(process_name)? {
            if !process_matches_dir(&process, dir, exact_exe_path)? {
                continue;
            }

            info!(
                "Stopping {} process {} from managed path {}",
                process_name,
                format_process_info(&process),
                dir.display()
            );
            stop_pid(process.id)?;
            matched_pids.push(process.id);
        }

        if matched_pids.is_empty() {
            return Ok(());
        }

        let mut remaining = vec![];
        for process in list_named_processes(process_name)? {
            if process_matches_dir(&process, dir, exact_exe_path)? {
                remaining.push(format_process_info(&process));
            }
        }

        if remaining.is_empty() {
            Ok(())
        } else {
            bail!(
                "{} processes are still running from {}:\n- {}",
                process_name,
                dir.display(),
                remaining.join("\n- ")
            )
        }
    }

    #[cfg(windows)]
    fn stop_pid(pid: u32) -> Result<()> {
        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .context(format!("Failed to stop process {}", pid))?;

        if !status.success() {
            bail!("taskkill failed for PID {}", pid);
        }

        let started = std::time::Instant::now();
        while started.elapsed() < PROCESS_STOP_TIMEOUT {
            if !is_pid_running(pid) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        bail!("Process {} did not exit after taskkill", pid)
    }

    #[cfg(windows)]
    fn role_paths(role: &str) -> Result<(PathBuf, PathBuf)> {
        match role {
            ROLE_SURICATA => Ok((get_suricata_pid_path()?, get_suricata_runtime_path()?)),
            ROLE_EVEBOX => Ok((get_evebox_pid_path()?, get_evebox_runtime_path()?)),
            ROLE_EVEBOX_AGENT => Ok((
                get_evebox_agent_pid_path()?,
                get_evebox_agent_runtime_path()?,
            )),
            _ => bail!("Unknown runtime role {}", role),
        }
    }

    #[cfg(windows)]
    fn cleanup_runtime_files(role: &str) -> Result<()> {
        let (pid_path, runtime_path) = role_paths(role)?;
        remove_file_if_exists(&pid_path)?;
        remove_file_if_exists(&runtime_path)?;
        Ok(())
    }

    #[cfg(windows)]
    fn managed_process_is_running(role: &str) -> Result<bool> {
        let (pid_path, runtime_path) = role_paths(role)?;
        let metadata = match read_runtime_metadata(&runtime_path)? {
            Some(metadata) => metadata,
            None => {
                if pid_path.exists() {
                    remove_file_if_exists(&pid_path)?;
                }
                return Ok(false);
            }
        };

        if metadata.role != role {
            warn!(
                "Runtime metadata {} belongs to role {} instead of {}. Cleaning it up.",
                runtime_path.display(),
                metadata.role,
                role
            );
            cleanup_runtime_files(role)?;
            return Ok(false);
        }

        if !is_pid_running(metadata.pid) {
            cleanup_runtime_files(role)?;
            return Ok(false);
        }

        if !process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
            warn!(
                "PID {} for role {} no longer matches {}. Cleaning up stale state.",
                metadata.pid, role, metadata.exe_path
            );
            cleanup_runtime_files(role)?;
            return Ok(false);
        }

        if let Some(pid) = read_pid(&pid_path)?
            && pid != metadata.pid
        {
            warn!(
                "PID file {} disagrees with runtime metadata for role {}. Rewriting it.",
                pid_path.display(),
                role
            );
            write_pid(&pid_path, metadata.pid)?;
        }

        Ok(true)
    }

    #[cfg(windows)]
    fn stop_managed_process(role: &str) -> Result<()> {
        let (pid_path, runtime_path) = role_paths(role)?;
        let metadata = match read_runtime_metadata(&runtime_path)? {
            Some(metadata) => metadata,
            None => {
                remove_file_if_exists(&pid_path)?;
                return Ok(());
            }
        };

        if metadata.role != role {
            warn!(
                "Runtime metadata {} belongs to role {} instead of {}. Removing stale state.",
                runtime_path.display(),
                metadata.role,
                role
            );
            cleanup_runtime_files(role)?;
            return Ok(());
        }

        let pid_running = is_pid_running(metadata.pid);
        if pid_running && process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
            info!("Stopping {} process with PID {}", role, metadata.pid);
            stop_pid(metadata.pid)?;
        } else if pid_running {
            warn!(
                "Refusing to stop PID {} for role {} because it no longer matches {}",
                metadata.pid, role, metadata.exe_path
            );
        }

        cleanup_runtime_files(role)
    }

    /// True when a prompt error is the user backing out (ESC or Ctrl-C)
    /// rather than a real failure.
    #[cfg(windows)]
    fn prompt_was_cancelled(err: &anyhow::Error) -> bool {
        matches!(
            err.downcast_ref::<inquire::InquireError>(),
            Some(
                inquire::InquireError::OperationCanceled
                    | inquire::InquireError::OperationInterrupted
            )
        )
    }

    #[cfg(windows)]
    fn prompt_for_interface(prompt: &str) -> Result<WindowsInterface> {
        let interfaces = get_windows_interfaces()?;
        if interfaces.is_empty() {
            bail!("No network interfaces found");
        }

        let mut selections = crate::prompt::Selections::with_index();
        for interface in &interfaces {
            let address = if interface.ip_address.is_empty() {
                "".to_string()
            } else {
                format!("-- {}", interface.ip_address.green().italic())
            };
            selections.push(interface.clone(), format!("{} {}", interface.name, address));
        }

        let selection = inquire::Select::new(prompt, selections.to_vec()).prompt()?;
        Ok(selection.tag)
    }

    #[cfg(windows)]
    fn prompt_for_interface_and_maybe_save() -> Result<WindowsInterface> {
        let interface =
            prompt_for_interface("Suricata: What network interface should Suricata listen on?")?;

        if inquire::Confirm::new("Remember this interface for future runs?")
            .with_default(true)
            .prompt()?
        {
            let config_path = set_configured_interface_name(&interface.name)?;
            println!("Saved default interface: {}", interface.name);
            println!("Resolved interface GUID: {}", interface.guid);
            println!("Config file: {}", config_path.display());
        }

        Ok(interface)
    }

    #[cfg(windows)]
    fn resolve_interface_guid(guid: Option<String>, allow_prompt: bool) -> Result<String> {
        if let Some(value) = guid.as_deref().and_then(normalize_interface_name) {
            if let Some(guid) = normalize_interface_guid(&value) {
                return Ok(guid);
            }

            if let Some(interface) = find_windows_interface_by_name(&value)? {
                return Ok(interface.guid);
            }

            bail!("Network interface '{}' was not found", value);
        }

        if let Some(guid) = get_configured_interface_guid()? {
            return Ok(guid);
        }

        if allow_prompt {
            Ok(prompt_for_interface_and_maybe_save()?.guid)
        } else {
            bail!(
                "No interface is configured. Use 'evectl config set-interface', pass --guid <GUID>, or run interactively to choose one."
            )
        }
    }

    #[cfg(windows)]
    fn config_set_interface() -> Result<()> {
        let interface = prompt_for_interface("Select Interface")?;
        let config_path = set_configured_interface_name(&interface.name)?;

        println!("Saved default interface: {}", interface.name);
        println!("Resolved interface GUID: {}", interface.guid);
        println!("Config file: {}", config_path.display());

        Ok(())
    }

    #[cfg(windows)]
    fn project_info() -> Result<()> {
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
            "  EveBox PID file:           {}",
            get_evebox_pid_path()?.display()
        );
        println!(
            "  EveBox runtime metadata:   {}",
            get_evebox_runtime_path()?.display()
        );
        if let Some(evebox_exe) = evebox_exe {
            println!("  Current EveBox binary:     {}", evebox_exe.display());
        } else {
            println!(
                "  Current EveBox binary:     {} (not installed)",
                evebox_install_dir.join("evebox.exe").display()
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn download_file(url: &str, path: &std::path::Path, name: &str) -> Result<()> {
        use std::fs::File;
        use std::io::{Read, Write};

        info!("Downloading {} from {}", name, url);
        info!("Saving to {:?}", path);

        let mut response =
            reqwest::blocking::get(url).context(format!("Failed to download {}", name))?;

        if !response.status().is_success() {
            bail!("Failed to download {}: HTTP {}", name, response.status());
        }

        let total_size = response.content_length().unwrap_or(0);
        let mut file = File::create(path).context(format!("Failed to create file for {}", name))?;

        let pb = if total_size > 0 {
            let pb = ProgressBar::new(total_size);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
                .progress_chars("#>-"));
            pb
        } else {
            ProgressBar::new_spinner()
        };

        let mut downloaded = 0u64;
        let mut buffer = [0; 8192];

        loop {
            let bytes_read = response.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            file.write_all(&buffer[..bytes_read])?;
            downloaded += bytes_read as u64;
            pb.set_position(downloaded);
        }

        pb.finish_with_message("Download complete");
        file.flush()?;
        drop(file);

        info!("Downloaded {} to {:?}", name, path);
        Ok(())
    }

    #[cfg(windows)]
    fn download_npcap() -> Result<()> {
        install_or_upgrade_npcap(false)
    }

    #[cfg(windows)]
    fn install_or_upgrade_npcap(upgrade: bool) -> Result<()> {
        let installed = is_npcap_installed();
        let should_mark_as_managed = !installed;

        if installed && !upgrade {
            info!("Npcap is already installed on this system.");
            return Ok(());
        }

        if upgrade {
            if installed {
                info!("Upgrading Npcap to version {}...", NPCAP_VERSION);
            } else {
                info!(
                    "Npcap was not detected. Installing version {} instead...",
                    NPCAP_VERSION
                );
            }
        }

        let url = format!("https://npcap.com/dist/npcap-{}.exe", NPCAP_VERSION);
        let temp_dir = tempfile::tempdir()?;
        let exe_path = temp_dir.path().join(format!("npcap-{}.exe", NPCAP_VERSION));

        download_file(&url, &exe_path, "Npcap")?;

        info!("Launching Npcap installer...");

        #[cfg(windows)]
        {
            launch_windows_installer(&exe_path, "Npcap", false)?;
            wait_for_installer_completion()?;
        }

        #[cfg(not(windows))]
        {
            use std::process::Command;

            let status = Command::new(&exe_path)
                .spawn()
                .context("Failed to launch Npcap installer")?
                .wait()
                .context("Failed to wait for Npcap installer")?;

            if !status.success() {
                bail!("Npcap installer exited with status: {}", status);
            }
        }

        if should_mark_as_managed {
            if is_npcap_installed() {
                mark_npcap_managed_installed()?;
                info!("Recorded Npcap as installed by evectl.");
            } else {
                warn!(
                    "Npcap installer completed, but Npcap was not detected afterwards. Not recording evectl ownership."
                );
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn launch_windows_installer(path: &std::path::Path, name: &str, elevated: bool) -> Result<()> {
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        use windows::core::PCWSTR;

        let path_str = path.to_string_lossy();
        let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let verb = if elevated { "runas" } else { "open" }
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();

        unsafe {
            let result = ShellExecuteW(
                None,
                PCWSTR(verb.as_ptr()),
                PCWSTR(path_wide.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );

            if result.0 as usize <= 32 {
                bail!(
                    "Failed to launch {} installer. Error code: {:?}",
                    name,
                    result.0
                );
            }
        }

        info!("{} installer launched successfully", name);
        Ok(())
    }

    #[cfg(windows)]
    fn wait_for_installer_completion() -> Result<()> {
        use std::io::{self, Write};

        info!("Please complete the installation in the opened window.");
        print!("Press Enter when the installation is complete to continue...");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        Ok(())
    }

    #[cfg(windows)]
    fn get_evectl_data_dir() -> Result<std::path::PathBuf> {
        Ok(dirs::data_local_dir()
            .ok_or_else(|| anyhow!("Could not find local data directory"))?
            .join("evectl"))
    }

    #[cfg(windows)]
    fn get_evectl_config_path() -> Result<PathBuf> {
        Ok(get_evectl_data_dir()?.join("evectl.toml"))
    }

    #[cfg(windows)]
    fn get_npcap_installed_marker_path() -> Result<PathBuf> {
        Ok(get_evectl_data_dir()?.join(NPCAP_INSTALLED_MARKER))
    }

    #[cfg(windows)]
    fn is_npcap_managed_installed() -> Result<bool> {
        Ok(get_npcap_installed_marker_path()?.exists())
    }

    #[cfg(windows)]
    fn mark_npcap_managed_installed() -> Result<()> {
        let data_dir = get_evectl_data_dir()?;
        ensure_dir(&data_dir)?;

        let marker_path = get_npcap_installed_marker_path()?;
        std::fs::write(
            &marker_path,
            format!("version={NPCAP_VERSION}\ninstalled_by=evectl\n"),
        )
        .context(format!("Failed to write {}", marker_path.display()))
    }

    #[cfg(windows)]
    fn clear_npcap_managed_installed_marker() -> Result<()> {
        let marker_path = get_npcap_installed_marker_path()?;
        if marker_path.exists() {
            std::fs::remove_file(&marker_path)
                .context(format!("Failed to remove {}", marker_path.display()))?;
        }

        Ok(())
    }

    #[cfg(windows)]
    fn get_desktop_dir() -> Result<PathBuf> {
        dirs::desktop_dir().ok_or_else(|| anyhow!("Could not find desktop directory"))
    }

    #[cfg(windows)]
    fn add_shortcuts() -> Result<()> {
        let desktop_dir = get_desktop_dir()?;
        let evectl_exe =
            std::env::current_exe().context("Failed to locate current EveCtl executable")?;

        let start_shortcut = desktop_dir.join(START_SHORTCUT_NAME);
        let evebox_shortcut = desktop_dir.join(EVEBOX_SHORTCUT_NAME);

        // The shortcut runs the stack in the foreground so the console
        // window shows the logs and closing it stops the stack.
        let start_contents = format!(
            "@echo off\r\n\"{}\" start --debug\r\n",
            evectl_exe.display()
        );
        std::fs::write(&start_shortcut, start_contents).context(format!(
            "Failed to write desktop shortcut {}",
            start_shortcut.display()
        ))?;

        let evebox_contents = format!(
            "[InternetShortcut]\r\nURL={}\r\n",
            EVEBOX_DESKTOP_SHORTCUT_URL
        );
        std::fs::write(&evebox_shortcut, evebox_contents).context(format!(
            "Failed to write desktop shortcut {}",
            evebox_shortcut.display()
        ))?;

        println!("Created desktop shortcuts:");
        println!("  Start:  {}", start_shortcut.display());
        println!("  EveBox: {}", evebox_shortcut.display());
        println!("  EveBox URL: {}", EVEBOX_DESKTOP_SHORTCUT_URL);

        Ok(())
    }

    #[cfg(windows)]
    fn load_evectl_config() -> Result<crate::config::Config> {
        let config_path = get_evectl_config_path()?;
        if config_path.exists() {
            crate::config::Config::from_file(&config_path)
        } else {
            Ok(crate::config::Config::default_with_filename(&config_path))
        }
    }

    #[cfg(windows)]
    fn normalize_interface_name(value: &str) -> Option<String> {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    }

    #[cfg(windows)]
    fn is_windows_interface_guid(value: &str) -> bool {
        let bytes = value.as_bytes();
        if bytes.len() != 36 {
            return false;
        }

        for (index, byte) in bytes.iter().enumerate() {
            match index {
                8 | 13 | 18 | 23 => {
                    if *byte != b'-' {
                        return false;
                    }
                }
                _ => {
                    if !(*byte as char).is_ascii_hexdigit() {
                        return false;
                    }
                }
            }
        }

        true
    }

    #[cfg(windows)]
    fn normalize_interface_guid(value: &str) -> Option<String> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }

        let value = value
            .strip_prefix(r"\Device\NPF_")
            .or_else(|| value.strip_prefix(r"\device\npf_"))
            .unwrap_or(value)
            .trim_matches(['{', '}']);

        if is_windows_interface_guid(value) {
            Some(value.to_ascii_uppercase())
        } else {
            None
        }
    }

    #[cfg(windows)]
    fn get_configured_interface_value() -> Result<Option<String>> {
        let config = load_evectl_config()?;
        Ok(config
            .suricata
            .interfaces
            .first()
            .and_then(|value| normalize_interface_name(value)))
    }

    #[cfg(windows)]
    fn find_windows_interface_by_name(name: &str) -> Result<Option<WindowsInterface>> {
        let name = match normalize_interface_name(name) {
            Some(name) => name,
            None => return Ok(None),
        };

        Ok(get_windows_interfaces()?
            .into_iter()
            .find(|interface| interface.name.eq_ignore_ascii_case(&name)))
    }

    #[cfg(windows)]
    fn find_windows_interface_by_guid(guid: &str) -> Result<Option<WindowsInterface>> {
        let guid = match normalize_interface_guid(guid) {
            Some(guid) => guid,
            None => return Ok(None),
        };

        Ok(get_windows_interfaces()?.into_iter().find(|interface| {
            normalize_interface_guid(&interface.guid).as_deref() == Some(guid.as_str())
        }))
    }

    #[cfg(windows)]
    fn get_configured_interface_guid() -> Result<Option<String>> {
        let value = match get_configured_interface_value()? {
            Some(value) => value,
            None => return Ok(None),
        };

        if let Some(guid) = normalize_interface_guid(&value) {
            return Ok(Some(guid));
        }

        Ok(find_windows_interface_by_name(&value)?.map(|interface| interface.guid))
    }

    #[cfg(windows)]
    fn set_configured_interface_name(name: &str) -> Result<PathBuf> {
        let config_path = get_evectl_config_path()?;
        ensure_dir(&get_evectl_data_dir()?)?;

        let mut config = load_evectl_config()?;
        config.suricata.interfaces = vec![name.to_string()];
        config.save()?;

        Ok(config_path)
    }

    #[cfg(windows)]
    fn get_suricata_data_dir() -> Result<std::path::PathBuf> {
        Ok(get_evectl_data_dir()?.join("suricata"))
    }

    #[cfg(windows)]
    fn get_suricata_run_dir() -> Result<PathBuf> {
        Ok(get_suricata_data_dir()?.join("run"))
    }

    #[cfg(windows)]
    fn get_suricata_log_dir() -> Result<PathBuf> {
        Ok(get_suricata_data_dir()?.join("log"))
    }

    #[cfg(windows)]
    fn get_suricata_install_dir() -> Result<std::path::PathBuf> {
        Ok(get_suricata_data_dir()?.join("install"))
    }

    #[cfg(windows)]
    fn get_suricata_exe_path() -> Result<std::path::PathBuf> {
        Ok(get_suricata_install_dir()?.join("suricata.exe"))
    }

    #[cfg(windows)]
    fn get_suricata_version_marker_path() -> Result<std::path::PathBuf> {
        Ok(get_suricata_install_dir()?.join(SURICATA_VERSION_MARKER))
    }

    #[cfg(windows)]
    fn get_suricata_pid_path() -> Result<PathBuf> {
        Ok(get_suricata_run_dir()?.join("suricata.pid"))
    }

    #[cfg(windows)]
    fn get_suricata_runtime_path() -> Result<PathBuf> {
        Ok(get_suricata_run_dir()?.join("suricata.runtime.json"))
    }

    #[cfg(windows)]
    fn get_suricata_stdout_log_path() -> Result<PathBuf> {
        Ok(get_suricata_log_dir()?.join("suricata-stdout.log"))
    }

    #[cfg(windows)]
    fn get_suricata_stderr_log_path() -> Result<PathBuf> {
        Ok(get_suricata_log_dir()?.join("suricata-stderr.log"))
    }

    #[cfg(windows)]
    fn get_suricata_eve_json_path() -> Result<PathBuf> {
        Ok(get_suricata_log_dir()?.join("eve.json"))
    }

    #[cfg(windows)]
    fn get_suricata_threshold_config_path() -> Result<PathBuf> {
        Ok(get_suricata_run_dir()?.join("threshold.config"))
    }

    #[cfg(windows)]
    fn ensure_suricata_threshold_config() -> Result<PathBuf> {
        let path = get_suricata_threshold_config_path()?;
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }

        if !path.exists() {
            std::fs::write(&path, b"").context(format!(
                "Failed to create Suricata threshold config {}",
                path.display()
            ))?;
        }

        Ok(path)
    }

    #[cfg(windows)]
    fn find_suricata_executable() -> Option<std::path::PathBuf> {
        use std::process::Command;

        if let Ok(path) = get_suricata_exe_path()
            && path.exists()
        {
            return Some(path);
        }

        for path in &SURICATA_SYSTEM_EXE_PATHS {
            let path = std::path::PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }

        if let Ok(output) = Command::new("where").arg("suricata.exe").output()
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(path) = stdout.lines().map(str::trim).find(|line| !line.is_empty()) {
                let path = std::path::PathBuf::from(path);
                if path.exists() {
                    return Some(path);
                }
            }
        }

        None
    }

    #[cfg(windows)]
    fn find_file_recursive(
        root: &std::path::Path,
        target_filename: &str,
    ) -> Result<Option<std::path::PathBuf>> {
        let mut stack = vec![root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)
                .context(format!("Failed to read directory {}", dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;

                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }

                if file_type.is_file()
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .eq_ignore_ascii_case(target_filename)
                {
                    return Ok(Some(path));
                }
            }
        }

        Ok(None)
    }

    #[cfg(windows)]
    fn find_suricata_install_file(
        install_dir: &std::path::Path,
        filename: &str,
    ) -> Option<std::path::PathBuf> {
        let candidates = [
            install_dir.join(filename),
            install_dir.join("etc").join(filename),
        ];

        for candidate in candidates {
            if candidate.exists() {
                return Some(candidate);
            }
        }

        match find_file_recursive(install_dir, filename) {
            Ok(path) => path,
            Err(err) => {
                warn!(
                    "Failed to search for {} under {}: {}",
                    filename,
                    install_dir.display(),
                    err
                );
                None
            }
        }
    }

    #[cfg(windows)]
    fn copy_dir_recursive(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(destination).context(format!(
            "Failed to create destination directory {}",
            destination.display()
        ))?;

        for entry in std::fs::read_dir(source).context(format!(
            "Failed to read source directory {}",
            source.display()
        ))? {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let file_type = entry.file_type()?;

            if file_type.is_dir() {
                copy_dir_recursive(&source_path, &destination_path)?;
            } else if file_type.is_file() {
                std::fs::copy(&source_path, &destination_path).context(format!(
                    "Failed to copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                ))?;
            }
        }

        Ok(())
    }

    #[cfg(windows)]
    fn patch_suricata_config_for_local_install(install_dir: &std::path::Path) -> Result<()> {
        let config_path = install_dir.join("suricata.yaml");
        if !config_path.exists() {
            return Ok(());
        }

        let original = std::fs::read_to_string(&config_path)
            .context(format!("Failed to read {}", config_path.display()))?;

        let install_dir_str = install_dir.display().to_string().replace('/', "\\");
        let patched = original
            .replace(r"C:\Program Files\Suricata", &install_dir_str)
            .replace(r"C:\Program Files (x86)\Suricata", &install_dir_str);

        if patched != original {
            std::fs::write(&config_path, patched)
                .context(format!("Failed to write {}", config_path.display()))?;
            info!(
                "Patched Suricata config paths for local install at {}",
                config_path.display()
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn extract_msi_package_to_dir(
        path: &std::path::Path,
        name: &str,
        destination: &std::path::Path,
    ) -> Result<()> {
        use std::process::Command;

        info!(
            "Extracting {} from {:?} into {}",
            name,
            path,
            destination.display()
        );

        let staging_dir =
            tempfile::tempdir().context("Failed to create MSI extraction directory")?;
        let log_path =
            std::env::temp_dir().join(format!("evectl-{}-extract.log", name.to_ascii_lowercase()));

        let msi_path = path.to_string_lossy().replace('\'', "''");
        let target_dir = staging_dir.path().to_string_lossy().replace('\'', "''");
        let log_path_str = log_path.to_string_lossy().replace('\'', "''");

        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$msiPath = '{}'
$targetDir = '{}'
$logPath = '{}'
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
$argumentList = @('/a', $msiPath, '/qn', '/norestart', ('TARGETDIR=' + $targetDir), '/L*v', $logPath)
$process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argumentList -Wait -PassThru
exit $process.ExitCode
"#,
            msi_path, target_dir, log_path_str
        );

        let output = Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(&script)
            .output()
            .context(format!("Failed to extract {} MSI", name))?;

        let stderr = String::from_utf8_lossy(&output.stderr);

        match output.status.code() {
            Some(0) => {
                info!("{} extraction completed successfully", name);
            }
            Some(3010) | Some(1641) => {
                warn!(
                    "{} extraction completed, but a system reboot was requested by Windows Installer",
                    name
                );
            }
            Some(1223) => bail!("{} extraction was cancelled at the UAC prompt", name),
            Some(code) => bail!(
                "{} extraction failed with code {}. MSI log: {:?}. {}",
                name,
                code,
                log_path,
                stderr.trim()
            ),
            None => bail!("{} extraction terminated unexpectedly", name),
        }

        let extracted_exe = find_file_recursive(staging_dir.path(), "suricata.exe")?
            .ok_or_else(|| anyhow!("Failed to locate suricata.exe in extracted MSI contents"))?;

        let extracted_root = extracted_exe.parent().ok_or_else(|| {
            anyhow!(
                "Failed to determine extracted Suricata root from {}",
                extracted_exe.display()
            )
        })?;

        if destination.exists() {
            std::fs::remove_dir_all(destination).context(format!(
                "Failed to remove existing Suricata directory {}",
                destination.display()
            ))?;
        }

        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .context(format!("Failed to create {}", parent.display()))?;
        }

        copy_dir_recursive(extracted_root, destination)?;

        Ok(())
    }

    #[cfg(windows)]
    fn is_npcap_installed() -> bool {
        let service_exists = ["npcap", "npf"].iter().any(|service| {
            std::process::Command::new("sc")
                .args(["query", service])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        });

        if !service_exists {
            return false;
        }

        [
            r"C:\Windows\System32\drivers\npcap.sys",
            r"C:\Windows\System32\drivers\npf.sys",
        ]
        .iter()
        .any(|path| std::path::Path::new(path).exists())
    }

    #[cfg(windows)]
    fn is_suricata_managed_installed() -> bool {
        get_suricata_exe_path()
            .map(|path| path.exists())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    fn is_suricata_installed() -> bool {
        if find_suricata_executable().is_some() {
            return true;
        }

        // Check if Suricata service exists
        if let Ok(output) = std::process::Command::new("sc")
            .args(["query", "Suricata"])
            .output()
            && output.status.success()
        {
            return true;
        }

        false
    }

    /// Install what the configuration calls for, running the setup
    /// wizard first if nothing has been configured yet.
    #[cfg(windows)]
    fn install() -> Result<()> {
        let mut config = load_evectl_config()?;
        install_with(&mut config)
    }

    #[cfg(windows)]
    fn install_with(config: &mut crate::config::Config) -> Result<()> {
        if !(config.suricata.enabled || config.evebox_server.enabled || config.evebox_agent.enabled)
        {
            return wizard(config);
        }

        install_configured_components(config)
    }

    /// Install the components required by the enabled services: Npcap and
    /// Suricata only when Suricata is enabled, EveBox for a server or
    /// agent.
    #[cfg(windows)]
    fn install_configured_components(config: &crate::config::Config) -> Result<()> {
        if config.suricata.enabled {
            download_npcap()?;
            install_or_upgrade_suricata(false)?;
        }

        if config.evebox_server.enabled || config.evebox_agent.enabled {
            install_evebox()?;
        }

        Ok(())
    }

    #[cfg(windows)]
    fn npcap_upgrade_needed() -> Result<bool> {
        if !is_npcap_installed() {
            return Ok(true);
        }

        let Some(installed_version) = get_npcap_installed_version()? else {
            return Ok(false);
        };

        let Some(comparison) = compare_versions(&installed_version, NPCAP_VERSION) else {
            return Ok(false);
        };

        Ok(comparison == std::cmp::Ordering::Less)
    }

    #[cfg(windows)]
    fn suricata_upgrade_needed() -> Result<bool> {
        let target_version = suricata_version_for_comparison();

        if !is_suricata_managed_installed() {
            return Ok(true);
        }

        let installed_version = match get_suricata_installed_version()? {
            Some(version) => version,
            None => return Ok(true),
        };

        let Some(comparison) = compare_versions(&installed_version, target_version) else {
            return Ok(false);
        };

        Ok(comparison == std::cmp::Ordering::Less)
    }

    #[cfg(windows)]
    fn evebox_upgrade_needed() -> Result<bool> {
        if find_evebox_exe(&get_evebox_install_dir()?)?.is_none() {
            return Ok(true);
        }

        let Some(installed_version) = get_evebox_installed_version()? else {
            return Ok(true);
        };

        let Some(comparison) = compare_versions(&installed_version, EVEBOX_VERSION) else {
            return Ok(false);
        };

        Ok(comparison == std::cmp::Ordering::Less)
    }

    /// Only the components required by the enabled services are
    /// considered for upgrade; a server-only install for example must
    /// not pull in Npcap or Suricata.
    #[cfg(windows)]
    fn build_upgrade_plan() -> Result<UpgradePlan> {
        let config = load_evectl_config()?;
        let use_suricata = config.suricata.enabled;
        let use_evebox = config.evebox_server.enabled || config.evebox_agent.enabled;

        Ok(UpgradePlan {
            npcap: use_suricata && npcap_upgrade_needed()?,
            suricata: use_suricata && suricata_upgrade_needed()?,
            evebox: use_evebox && evebox_upgrade_needed()?,
        })
    }

    #[cfg(windows)]
    fn get_managed_runtime_metadata(role: &str) -> Result<Option<RuntimeMetadata>> {
        if !managed_process_is_running(role)? {
            return Ok(None);
        }

        let (_, runtime_path) = role_paths(role)?;
        read_runtime_metadata(&runtime_path)
    }

    #[cfg(windows)]
    fn suricata_guid_from_metadata(metadata: &RuntimeMetadata) -> Option<String> {
        metadata.argv.windows(2).find_map(|window| {
            if window[0] == "-i" {
                normalize_interface_guid(&window[1])
            } else {
                None
            }
        })
    }

    #[cfg(windows)]
    fn capture_restart_plan() -> Result<RestartPlan> {
        let suricata_running = get_managed_runtime_metadata(ROLE_SURICATA)?;
        let suricata_guid = suricata_running
            .as_ref()
            .and_then(suricata_guid_from_metadata)
            .or_else(|| get_configured_interface_guid().ok().flatten());

        let evebox_server_running = get_managed_runtime_metadata(ROLE_EVEBOX)?.is_some();
        let evebox_agent_running = get_managed_runtime_metadata(ROLE_EVEBOX_AGENT)?.is_some();

        Ok(RestartPlan {
            suricata_running: suricata_running.is_some(),
            suricata_guid,
            evebox_server_running,
            evebox_agent_running,
        })
    }

    #[cfg(windows)]
    fn restart_managed_components(plan: &RestartPlan) -> Result<()> {
        let result = (|| {
            if plan.suricata_running {
                let guid = plan.suricata_guid.as_deref().ok_or_else(|| {
                    anyhow!(
                        "Failed to determine the interface GUID used by the previously running Suricata process"
                    )
                })?;

                let suricata = start_suricata_background(guid)?;
                wait_for_suricata_readiness(&suricata)?;
            }

            if plan.evebox_server_running {
                let evebox = start_evebox_background()?;
                validate_background_process_started(&evebox)?;
            }

            if plan.evebox_agent_running {
                let agent = start_evebox_agent_background()?;
                validate_background_process_started(&agent)?;
            }

            Ok(())
        })();

        if result.is_err() {
            let _ = stop_stack();
        }

        result
    }

    #[cfg(windows)]
    fn upgrade_windows_components() -> Result<()> {
        // Update EveCtl itself first, matching the Linux update workflow. On
        // Windows the new executable is staged and applied on the next start,
        // so the component upgrades below still run with the current binary.
        if let Err(err) = crate::selfupdate::self_update() {
            error!("Failed to update EveCtl: {err}");
            info!("Continuing with component updates");
        }

        let plan = build_upgrade_plan()?;
        if !plan.any() {
            info!("No component upgrades are available.");
            return Ok(());
        }

        let restart_plan = capture_restart_plan()?;
        if restart_plan.any() {
            info!("Stopping managed Windows services before upgrade");
            stop_stack()?;
        }

        let upgrade_result = (|| {
            maybe_upgrade_npcap()?;
            maybe_upgrade_suricata()?;
            maybe_upgrade_evebox()?;
            Ok(())
        })();

        if let Err(err) = upgrade_result {
            if restart_plan.any()
                && let Err(restart_err) = restart_managed_components(&restart_plan)
            {
                return Err(anyhow!(
                    "Upgrade failed: {}\nAdditionally failed to restart previously running services: {}",
                    err,
                    restart_err
                ));
            }
            return Err(err);
        }

        if restart_plan.any() {
            restart_managed_components(&restart_plan)?;
        }

        Ok(())
    }

    #[cfg(windows)]
    fn maybe_upgrade_npcap() -> Result<()> {
        if !is_npcap_installed() {
            info!(
                "Npcap was not detected. Installing version {} before Suricata upgrade...",
                NPCAP_VERSION
            );
            return install_or_upgrade_npcap(true);
        }

        let installed_version = match get_npcap_installed_version()? {
            Some(version) => version,
            None => {
                info!(
                    "Npcap is installed, but the installed version could not be determined. Skipping automatic Npcap upgrade."
                );
                return Ok(());
            }
        };

        let comparison = match compare_versions(&installed_version, NPCAP_VERSION) {
            Some(comparison) => comparison,
            None => {
                info!(
                    "Npcap version comparison failed (installed: {}, bundled: {}). Skipping automatic Npcap upgrade.",
                    installed_version, NPCAP_VERSION
                );
                return Ok(());
            }
        };

        match comparison {
            std::cmp::Ordering::Less => {
                info!(
                    "Npcap {} is older than bundled {}. Upgrading Npcap...",
                    installed_version, NPCAP_VERSION
                );
                install_or_upgrade_npcap(true)
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                info!(
                    "Npcap {} meets or exceeds bundled {}. Skipping Npcap upgrade.",
                    installed_version, NPCAP_VERSION
                );
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    fn get_npcap_installed_version() -> Result<Option<String>> {
        use std::process::Command;

        let script = r#"
$entry = @(
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Npcap*' } | Select-Object -First 1

if ($entry -and $entry.DisplayVersion) {
    Write-Output $entry.DisplayVersion
}
"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output()
            .context("Failed to query installed Npcap version")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "Failed to determine installed Npcap version: {}",
                stderr.trim()
            );
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let version = stdout.trim();
        if version.is_empty() {
            Ok(None)
        } else {
            Ok(Some(version.to_string()))
        }
    }

    #[cfg(windows)]
    fn compare_versions(current: &str, target: &str) -> Option<std::cmp::Ordering> {
        let current_parts = parse_version_parts(current)?;
        let target_parts = parse_version_parts(target)?;
        let max_len = current_parts.len().max(target_parts.len());

        for idx in 0..max_len {
            let lhs = *current_parts.get(idx).unwrap_or(&0);
            let rhs = *target_parts.get(idx).unwrap_or(&0);
            let ord = lhs.cmp(&rhs);
            if ord != std::cmp::Ordering::Equal {
                return Some(ord);
            }
        }

        Some(std::cmp::Ordering::Equal)
    }

    #[cfg(windows)]
    fn parse_version_parts(version: &str) -> Option<Vec<u32>> {
        let mut parts = vec![];
        let mut current = String::new();

        for ch in version.trim().chars() {
            if ch.is_ascii_digit() {
                current.push(ch);
            } else if !current.is_empty() {
                let value = match current.parse::<u32>() {
                    Ok(value) => value,
                    Err(_) => return None,
                };
                parts.push(value);
                current.clear();
            }
        }

        if !current.is_empty() {
            let value = match current.parse::<u32>() {
                Ok(value) => value,
                Err(_) => return None,
            };
            parts.push(value);
        }

        if parts.is_empty() { None } else { Some(parts) }
    }

    #[cfg(windows)]
    fn maybe_upgrade_suricata() -> Result<()> {
        let target_version = suricata_version_for_comparison();
        let managed_installed = is_suricata_managed_installed();
        let any_installed = is_suricata_installed();

        if !managed_installed {
            if any_installed {
                info!(
                    "A non-evectl Suricata installation was detected. Installing evectl-managed version {}...",
                    SURICATA_VERSION
                );
            } else {
                info!(
                    "Suricata was not detected. Installing version {}...",
                    SURICATA_VERSION
                );
            }
            return install_or_upgrade_suricata(true);
        }

        let installed_version = match get_suricata_installed_version()? {
            Some(version) => version,
            None => {
                info!(
                    "Suricata is installed in the evectl-managed directory, but the version could not be determined. Reinstalling bundled version {}.",
                    SURICATA_VERSION
                );
                return install_or_upgrade_suricata(true);
            }
        };

        let comparison = match compare_versions(&installed_version, target_version) {
            Some(comparison) => comparison,
            None => {
                info!(
                    "Suricata version comparison failed (installed: {}, bundled: {}, comparison target: {}). Skipping automatic Suricata upgrade.",
                    installed_version, SURICATA_VERSION, target_version
                );
                return Ok(());
            }
        };

        match comparison {
            std::cmp::Ordering::Less => {
                info!(
                    "Suricata {} is older than bundled {} (package {}). Upgrading Suricata...",
                    installed_version, target_version, SURICATA_VERSION
                );
                install_or_upgrade_suricata(true)
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                info!(
                    "Suricata {} meets or exceeds bundled {} (package {}). Skipping Suricata upgrade.",
                    installed_version, target_version, SURICATA_VERSION
                );
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    fn maybe_upgrade_evebox() -> Result<()> {
        if find_evebox_exe(&get_evebox_install_dir()?)?.is_none() {
            info!(
                "EveBox was not detected. Installing version {}...",
                EVEBOX_VERSION
            );
            return install_or_upgrade_evebox(true);
        }

        let installed_version = match get_evebox_installed_version()? {
            Some(version) => version,
            None => {
                info!(
                    "EveBox is installed in the evectl-managed directory, but the version could not be determined. Reinstalling bundled version {}.",
                    EVEBOX_VERSION
                );
                return install_or_upgrade_evebox(true);
            }
        };

        let comparison = match compare_versions(&installed_version, EVEBOX_VERSION) {
            Some(comparison) => comparison,
            None => {
                info!(
                    "EveBox version comparison failed (installed: {}, bundled: {}). Skipping automatic EveBox upgrade.",
                    installed_version, EVEBOX_VERSION
                );
                return Ok(());
            }
        };

        match comparison {
            std::cmp::Ordering::Less => {
                info!(
                    "EveBox {} is older than bundled {}. Upgrading EveBox...",
                    installed_version, EVEBOX_VERSION
                );
                install_or_upgrade_evebox(true)
            }
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {
                info!(
                    "EveBox {} meets or exceeds bundled {}. Skipping EveBox upgrade.",
                    installed_version, EVEBOX_VERSION
                );
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    fn suricata_version_for_comparison() -> &'static str {
        SURICATA_VERSION
            .split('-')
            .next()
            .unwrap_or(SURICATA_VERSION)
    }

    #[cfg(windows)]
    fn get_suricata_installed_version() -> Result<Option<String>> {
        if let Ok(marker_path) = get_suricata_version_marker_path()
            && marker_path.exists()
        {
            let version = std::fs::read_to_string(&marker_path).context(format!(
                "Failed to read Suricata version marker {}",
                marker_path.display()
            ))?;
            let version = version.trim();
            if !version.is_empty() {
                return Ok(Some(version.to_string()));
            }
        }

        Ok(None)
    }

    #[cfg(windows)]
    fn install_or_upgrade_suricata(upgrade: bool) -> Result<()> {
        let managed_installed = is_suricata_managed_installed();
        let any_installed = is_suricata_installed();

        if managed_installed && !upgrade {
            info!("Suricata is already installed in the evectl-managed directory.");
            return Ok(());
        }

        if any_installed
            && !managed_installed
            && !upgrade
            && let Ok(install_dir) = get_suricata_install_dir()
        {
            info!(
                "A system Suricata installation was detected. Installing an evectl-managed copy into {}.",
                install_dir.display()
            );
        }

        if upgrade {
            if managed_installed {
                info!("Upgrading Suricata to version {}...", SURICATA_VERSION);

                if let Err(err) = stop_suricata_managed() {
                    warn!("Failed to stop running Suricata processes: {}", err);
                }

                uninstall_suricata()?;
            } else if any_installed {
                info!(
                    "A non-evectl Suricata installation was detected. Installing evectl-managed version {} instead...",
                    SURICATA_VERSION
                );
            } else {
                info!(
                    "Suricata was not detected. Installing version {} instead...",
                    SURICATA_VERSION
                );
            }
        }

        let url = format!(
            "https://www.openinfosecfoundation.org/download/windows/Suricata-{}-64bit.msi",
            SURICATA_VERSION
        );
        let filename = format!("Suricata-{}-64bit.msi", SURICATA_VERSION);

        let cache_dir = get_evectl_data_dir()?.join("downloads");
        std::fs::create_dir_all(&cache_dir).context(format!(
            "Failed to create installer cache directory {}",
            cache_dir.display()
        ))?;

        let msi_path = cache_dir.join(&filename);

        if msi_path.exists() {
            info!("Suricata installer already exists at {:?}", msi_path);
            info!("Skipping download, using existing file");
        } else {
            download_file(&url, &msi_path, "Suricata")?;
        }

        let install_dir = get_suricata_install_dir()?;
        extract_msi_package_to_dir(&msi_path, "Suricata", &install_dir)?;
        patch_suricata_config_for_local_install(&install_dir)?;

        let marker_path = get_suricata_version_marker_path()?;
        std::fs::write(&marker_path, suricata_version_for_comparison()).context(format!(
            "Failed to write Suricata version marker {}",
            marker_path.display()
        ))?;

        let suricata_exe = get_suricata_exe_path()?;
        if !suricata_exe.exists() {
            bail!(
                "Suricata extraction completed, but executable not found at {}",
                suricata_exe.display()
            );
        }

        info!(
            "Suricata {} extracted to {}",
            SURICATA_VERSION,
            install_dir.display()
        );

        Ok(())
    }

    #[cfg(windows)]
    fn log_uninstall_process_diagnostics() -> Result<()> {
        let suricata_install_dir = get_suricata_install_dir()?;
        let suricata_exe_path = get_suricata_exe_path()?;
        log_processes_in_dir("suricata", &suricata_install_dir, Some(&suricata_exe_path))?;

        let evebox_install_dir = get_evebox_install_dir()?;
        let evebox_exe_path = find_evebox_exe(&evebox_install_dir)?;
        log_processes_in_dir("evebox", &evebox_install_dir, evebox_exe_path.as_deref())?;

        Ok(())
    }

    #[cfg(windows)]
    fn cleanup_suricata_leftovers() -> Result<()> {
        use std::process::Command;

        let mut errors = vec![];
        let install_dir = get_suricata_install_dir()?;

        if install_dir.exists() {
            info!("Removing Suricata directory {}", install_dir.display());

            if let Err(err) = std::fs::remove_dir_all(&install_dir) {
                warn!(
                    "Failed to remove {} directly: {}. Trying PowerShell cleanup...",
                    install_dir.display(),
                    err
                );

                let escaped = install_dir.to_string_lossy().replace('\'', "''");
                let script = format!(
                    "$ErrorActionPreference = 'Stop'; if (Test-Path -LiteralPath '{0}') {{ Remove-Item -LiteralPath '{0}' -Recurse -Force }}",
                    escaped
                );

                match Command::new("powershell")
                    .args(["-NoProfile", "-Command", &script])
                    .output()
                {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        errors.push(format!("{}: {}", install_dir.display(), stderr.trim()));
                    }
                    Err(ps_err) => {
                        errors.push(format!("{}: {}", install_dir.display(), ps_err));
                    }
                }
            }
        }

        if !errors.is_empty() {
            warn!(
                "Suricata uninstall cleanup hit file-lock or removal errors. This often means a non-Suricata process still has a handle open under the install directory (for example Explorer, antivirus, an editor, or another tool)."
            );
            bail!(
                "Failed to remove Suricata leftover files:\n- {}",
                errors.join("\n- ")
            );
        }

        let suricata_exe_path = get_suricata_exe_path()?;
        if suricata_exe_path.exists() {
            bail!(
                "Suricata uninstall completed, but this executable still exists:\n- {}",
                suricata_exe_path.display()
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn uninstall_suricata() -> Result<()> {
        info!("Removing evectl-managed Suricata installation...");
        cleanup_suricata_leftovers()
    }

    #[cfg(windows)]
    fn uninstall_npcap() -> Result<()> {
        use std::process::Command;

        if !is_npcap_managed_installed()? {
            if is_npcap_installed() {
                info!(
                    "Npcap is installed, but it was not installed by evectl. Skipping Npcap uninstall."
                );
            } else {
                info!("Npcap was not installed by evectl. Skipping Npcap uninstall.");
            }
            return Ok(());
        }

        if !is_npcap_installed() {
            info!(
                "Npcap was marked as installed by evectl, but no Npcap installation was detected. Clearing marker."
            );
            clear_npcap_managed_installed_marker()?;
            return Ok(());
        }

        info!("Uninstalling evectl-managed Npcap installation...");

        let script = r#"
$ErrorActionPreference = 'Stop'
$entry = @(
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
    Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue
) | Where-Object { $_.DisplayName -like 'Npcap*' } | Select-Object -First 1

if (-not $entry) {
    Write-Output 'NOT_FOUND'
    exit 0
}

$productCode = $entry.PSChildName
if ($productCode -match '^\{[0-9A-Fa-f\-]+\}$') {
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', $productCode, '/qn', '/norestart' -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
}

$command = $entry.QuietUninstallString
if ([string]::IsNullOrWhiteSpace($command)) {
    $command = $entry.UninstallString
}
if ([string]::IsNullOrWhiteSpace($command)) {
    throw 'Unable to determine Npcap uninstall command'
}

if ($command -match '(?i)msiexec(\.exe)?') {
    $command = $command -replace '(?i)\s/I(?=\s|\{)', ' /X'
    if ($command -notmatch '(?i)\s/(qn|quiet|passive)\b') {
        $command = "$command /qn"
    }
    if ($command -notmatch '(?i)\s/norestart\b') {
        $command = "$command /norestart"
    }
}

$process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/C', $command -Verb RunAs -Wait -PassThru
exit $process.ExitCode
"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output()
            .context("Failed to execute Npcap uninstall command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Npcap uninstall failed: {}", stderr.trim());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("NOT_FOUND") {
            info!("Npcap uninstall entry not found. Clearing evectl ownership marker.");
            clear_npcap_managed_installed_marker()?;
            return Ok(());
        }

        clear_npcap_managed_installed_marker()?;
        info!("Npcap uninstall completed");
        Ok(())
    }

    #[cfg(windows)]
    fn get_evebox_root_dir() -> Result<std::path::PathBuf> {
        Ok(get_evectl_data_dir()?.join("evebox"))
    }

    #[cfg(windows)]
    fn get_evebox_install_dir() -> Result<std::path::PathBuf> {
        Ok(get_evebox_root_dir()?.join("install"))
    }

    #[cfg(windows)]
    fn get_evebox_data_dir() -> Result<std::path::PathBuf> {
        Ok(get_evebox_root_dir()?.join("data"))
    }

    #[cfg(windows)]
    fn find_evebox_exe(dir: &Path) -> Result<Option<PathBuf>> {
        let direct_path = dir.join("evebox.exe");
        if direct_path.exists() {
            return Ok(Some(direct_path));
        }

        if !dir.exists() {
            return Ok(None);
        }

        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read EveBox directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            if let Some(exe_path) = find_evebox_exe(&path)? {
                return Ok(Some(exe_path));
            }
        }

        Ok(None)
    }

    #[cfg(windows)]
    fn get_evebox_exe_path() -> Result<PathBuf> {
        find_evebox_exe(&get_evebox_install_dir()?)?
            .ok_or_else(|| anyhow!("EveBox is not installed. Run 'evectl install' first."))
    }

    #[cfg(windows)]
    fn get_evebox_version_marker_path() -> Result<PathBuf> {
        Ok(get_evebox_install_dir()?.join(EVEBOX_VERSION_MARKER))
    }

    #[cfg(windows)]
    fn remove_existing_evebox_installation() -> Result<()> {
        let install_dir = get_evebox_install_dir()?;
        if !install_dir.exists() {
            return Ok(());
        }

        std::fs::remove_dir_all(&install_dir).context(format!(
            "Failed to remove existing EveBox install directory {}",
            install_dir.display()
        ))?;
        info!(
            "Removed previous EveBox install files from {} while preserving data in {}",
            install_dir.display(),
            get_evebox_data_dir()?.display()
        );

        Ok(())
    }

    #[cfg(windows)]
    fn extract_evebox_version_from_path(path: &Path) -> Option<String> {
        for component in path.components() {
            let name = component.as_os_str().to_string_lossy();
            if let Some(version) = name
                .strip_prefix("evebox-")
                .and_then(|rest| rest.strip_suffix("-windows-x64"))
                && !version.is_empty()
            {
                return Some(version.to_string());
            }
        }

        None
    }

    #[cfg(windows)]
    fn get_evebox_installed_version() -> Result<Option<String>> {
        if let Ok(marker_path) = get_evebox_version_marker_path()
            && marker_path.exists()
        {
            let version = std::fs::read_to_string(&marker_path).context(format!(
                "Failed to read EveBox version marker {}",
                marker_path.display()
            ))?;
            let version = version.trim();
            if !version.is_empty() {
                return Ok(Some(version.to_string()));
            }
        }

        let Some(exe_path) = find_evebox_exe(&get_evebox_install_dir()?)? else {
            return Ok(None);
        };

        Ok(extract_evebox_version_from_path(&exe_path))
    }

    #[cfg(windows)]
    fn get_evebox_pid_path() -> Result<PathBuf> {
        Ok(get_evebox_root_dir()?.join("evebox.pid"))
    }

    #[cfg(windows)]
    fn get_evebox_runtime_path() -> Result<PathBuf> {
        Ok(get_evebox_root_dir()?.join("evebox.runtime.json"))
    }

    #[cfg(windows)]
    fn get_evebox_agent_dir() -> Result<PathBuf> {
        Ok(get_evebox_root_dir()?.join("agent"))
    }

    #[cfg(windows)]
    fn get_evebox_agent_data_dir() -> Result<PathBuf> {
        Ok(get_evebox_agent_dir()?.join("data"))
    }

    #[cfg(windows)]
    fn get_evebox_agent_pid_path() -> Result<PathBuf> {
        Ok(get_evebox_agent_dir()?.join("evebox-agent.pid"))
    }

    #[cfg(windows)]
    fn get_evebox_agent_runtime_path() -> Result<PathBuf> {
        Ok(get_evebox_agent_dir()?.join("evebox-agent.runtime.json"))
    }

    #[cfg(windows)]
    fn uninstall_evebox() -> Result<()> {
        let root_dir = get_evebox_root_dir()?;

        if !root_dir.exists() {
            info!(
                "EveBox is not installed in {:?}. Skipping EveBox uninstall.",
                root_dir
            );
            return Ok(());
        }

        std::fs::remove_dir_all(&root_dir)
            .context(format!("Failed to remove EveBox directory {:?}", root_dir))?;
        info!("EveBox uninstalled from {:?}", root_dir);
        Ok(())
    }

    #[cfg(windows)]
    fn ensure_managed_services_stopped_for_uninstall() -> Result<()> {
        let any_running = managed_process_is_running(ROLE_SURICATA)?
            || managed_process_is_running(ROLE_EVEBOX)?
            || managed_process_is_running(ROLE_EVEBOX_AGENT)?;

        if !any_running {
            return Ok(());
        }

        info!("Stopping managed Windows services before uninstall");
        stop_stack().context("Failed to stop managed Windows stack before uninstall")?;

        if managed_process_is_running(ROLE_SURICATA)?
            || managed_process_is_running(ROLE_EVEBOX)?
            || managed_process_is_running(ROLE_EVEBOX_AGENT)?
        {
            bail!("Managed Windows services are still running after stop was requested");
        }

        Ok(())
    }

    #[cfg(windows)]
    fn ensure_unmanaged_evectl_processes_stopped_for_uninstall() -> Result<()> {
        let suricata_install_dir = get_suricata_install_dir()?;
        let suricata_exe_path = get_suricata_exe_path()?;
        stop_named_processes_in_dir("suricata", &suricata_install_dir, Some(&suricata_exe_path))?;

        let evebox_install_dir = get_evebox_install_dir()?;
        let evebox_exe_path = find_evebox_exe(&evebox_install_dir)?;
        stop_named_processes_in_dir("evebox", &evebox_install_dir, evebox_exe_path.as_deref())?;

        Ok(())
    }

    /// The directories and files holding runtime data: event data,
    /// logs, pid files, and the installer download cache.
    #[cfg(windows)]
    fn data_paths_for_uninstall() -> Result<Vec<PathBuf>> {
        Ok(vec![
            get_suricata_log_dir()?,
            get_suricata_run_dir()?,
            get_evebox_data_dir()?,
            get_evebox_agent_dir()?,
            get_evebox_pid_path()?,
            get_evebox_runtime_path()?,
            get_evectl_data_dir()?.join("downloads"),
        ])
    }

    /// The configuration paths. Suricata rules and ruleset selections
    /// count as configuration, matching the Linux layout where rules
    /// live under the config directory.
    #[cfg(windows)]
    fn config_paths_for_uninstall() -> Result<Vec<PathBuf>> {
        Ok(vec![
            get_evectl_config_path()?,
            get_suricata_data_dir()?.join("lib"),
        ])
    }

    #[cfg(windows)]
    fn existing_shortcuts() -> Result<Vec<PathBuf>> {
        let desktop_dir = get_desktop_dir()?;
        Ok([START_SHORTCUT_NAME, EVEBOX_SHORTCUT_NAME]
            .iter()
            .map(|name| desktop_dir.join(name))
            .filter(|path| path.exists())
            .collect())
    }

    /// A running executable can't delete itself on Windows, so hand
    /// the deletion to a detached helper that retries until this
    /// process has exited.
    #[cfg(windows)]
    fn schedule_self_delete(exe: &Path) -> Result<()> {
        // A staged self-update isn't locked and can go right away.
        if let Some(file_name) = exe.file_name().and_then(|name| name.to_str()) {
            let staged = exe.with_file_name(format!("{}.new", file_name));
            if staged.exists() {
                let _ = std::fs::remove_file(&staged);
            }
        }

        let script = r#"
$target = $env:EVECTL_SELF_DELETE_TARGET

for ($i = 0; $i -lt 120; $i++) {
    try {
        Remove-Item -LiteralPath $target -Force
        exit 0
    } catch {
        Start-Sleep -Milliseconds 250
    }
}

exit 1
"#;

        Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", script])
            .env("EVECTL_SELF_DELETE_TARGET", exe)
            .spawn()
            .context("Failed to launch self-delete helper")?;

        info!("{} will be removed after EveCtl exits", exe.display());
        Ok(())
    }

    /// Remove a file or directory, collecting any failure.
    #[cfg(windows)]
    fn remove_path(path: &Path, errors: &mut Vec<String>) {
        // The component uninstalls may have already removed it.
        if !path.exists() {
            return;
        }
        info!("Removing {}", path.display());
        let result = if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };
        if let Err(err) = result {
            errors.push(format!("Failed to remove {}: {}", path.display(), err));
        }
    }

    /// Uninstall EveBox, Suricata, and evectl-managed Npcap,
    /// collecting failures. Returns true if all succeeded.
    #[cfg(windows)]
    fn uninstall_components(errors: &mut Vec<String>) -> bool {
        // Informational only, so not fatal.
        if let Err(err) = log_uninstall_process_diagnostics() {
            warn!("Failed to log process diagnostics: {}", err);
        }

        let before = errors.len();

        if let Err(err) = uninstall_evebox() {
            errors.push(format!("EveBox uninstall failed: {}", err));
        }

        if let Err(err) = uninstall_suricata() {
            errors.push(format!("Suricata uninstall failed: {}", err));
        }

        if let Err(err) = uninstall_npcap() {
            errors.push(format!("Npcap uninstall failed: {}", err));
        }

        errors.len() == before
    }

    /// Uninstall the components, then remove the whole EveCtl
    /// directory. The directory holds the Npcap ownership marker and
    /// the version markers a retry needs, so it's left in place if any
    /// component uninstall failed.
    #[cfg(windows)]
    fn uninstall_components_and_directory(evectl_dir: &Path, errors: &mut Vec<String>) {
        if uninstall_components(errors) {
            remove_path(evectl_dir, errors);
        } else {
            warn!(
                "Leaving {} in place so the uninstall can be retried",
                evectl_dir.display()
            );
        }
    }

    #[cfg(windows)]
    fn uninstall(remove_config: bool, all: bool, yes: bool) -> Result<()> {
        let remove_config = remove_config || all;

        if !yes && !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            bail!("No terminal available for confirmation, pass --yes to run without prompting");
        }

        let evectl_dir = get_evectl_data_dir()?;
        let mut paths: Vec<PathBuf> = vec![];
        if !all {
            paths.extend(data_paths_for_uninstall()?);
            if remove_config {
                paths.extend(config_paths_for_uninstall()?);
            }
        }
        paths.retain(|path| path.exists());

        let shortcuts = if all { existing_shortcuts()? } else { vec![] };
        let mut binary = if all {
            crate::selfupdate::removable_exe()
        } else {
            None
        };

        println!("The following will be removed:");
        if all {
            println!("  EveBox, Suricata, and evectl-managed Npcap installations");
            println!("  {}", evectl_dir.display());
        }
        for path in paths.iter().chain(shortcuts.iter()) {
            println!("  {}", path.display());
        }
        if let Some(binary) = &binary {
            println!("  {}", binary.display());
        }

        if !yes && !crate::prompt::confirm_destructive("Proceed with uninstall?") {
            bail!("Uninstall canceled");
        }

        ensure_managed_services_stopped_for_uninstall()?;
        ensure_unmanaged_evectl_processes_stopped_for_uninstall()?;

        let mut errors: Vec<String> = vec![];

        if all {
            uninstall_components_and_directory(&evectl_dir, &mut errors);
        }

        for path in paths.iter().chain(shortcuts.iter()) {
            remove_path(path, &mut errors);
        }

        // When interactive, keep prompting through the layers the
        // flags didn't already cover: configuration, the EveCtl
        // directory, the desktop shortcuts, and finally the binary.
        if !yes && !all {
            let mut config_removed = true;

            if !remove_config {
                let rules_dir = get_suricata_data_dir()?.join("lib");
                if rules_dir.exists() {
                    if crate::prompt::confirm_destructive(&format!(
                        "Also remove the Suricata rules directory {}?",
                        rules_dir.display()
                    )) {
                        remove_path(&rules_dir, &mut errors);
                    } else {
                        config_removed = false;
                    }
                }

                let config_path = get_evectl_config_path()?;
                if config_path.exists() {
                    if crate::prompt::confirm_destructive(&format!(
                        "Also remove the configuration file {}?",
                        config_path.display()
                    )) {
                        remove_path(&config_path, &mut errors);
                    } else {
                        config_removed = false;
                    }
                }
            }

            // Only offer to remove the EveCtl directory once nothing
            // the user chose to keep remains in it. It holds the
            // installed components, which are uninstalled first.
            if config_removed
                && evectl_dir.exists()
                && crate::prompt::confirm_destructive(&format!(
                    "Also remove the EveCtl directory {} including the EveBox, Suricata, and evectl-managed Npcap installations?",
                    evectl_dir.display()
                ))
            {
                uninstall_components_and_directory(&evectl_dir, &mut errors);
            }

            let shortcuts = existing_shortcuts()?;
            if !shortcuts.is_empty()
                && crate::prompt::confirm_destructive("Also remove the desktop shortcuts?")
            {
                for path in &shortcuts {
                    remove_path(path, &mut errors);
                }
            }

            if let Some(exe) = crate::selfupdate::removable_exe()
                && crate::prompt::confirm_destructive(&format!(
                    "Also remove the EveCtl binary {}?",
                    exe.display()
                ))
            {
                binary = Some(exe);
            }
        }

        if let Some(binary) = &binary
            && let Err(err) = schedule_self_delete(binary)
        {
            errors.push(format!(
                "Failed to schedule removal of {}: {}",
                binary.display(),
                err
            ));
        }

        if errors.is_empty() {
            info!("Uninstall complete");
            Ok(())
        } else {
            bail!(
                "Uninstall completed with errors:\n- {}",
                errors.join("\n- ")
            )
        }
    }

    #[cfg(windows)]
    fn uninstall_windows_components() -> Result<()> {
        ensure_managed_services_stopped_for_uninstall()?;
        ensure_unmanaged_evectl_processes_stopped_for_uninstall()?;

        let mut errors: Vec<String> = vec![];
        if uninstall_components(&mut errors) {
            info!("Windows component uninstall completed");
            Ok(())
        } else {
            bail!(
                "Windows component uninstall completed with errors:\n- {}",
                errors.join("\n- ")
            )
        }
    }

    #[cfg(windows)]
    fn install_evebox() -> Result<()> {
        install_or_upgrade_evebox(false)
    }

    #[cfg(windows)]
    fn install_or_upgrade_evebox(upgrade: bool) -> Result<()> {
        let url = EVEBOX_URL;

        let root_dir = get_evebox_root_dir()?;
        let install_dir = get_evebox_install_dir()?;
        let data_dir = get_evebox_data_dir()?;

        std::fs::create_dir_all(&root_dir).context("Failed to create EveBox root directory")?;
        std::fs::create_dir_all(&data_dir).context("Failed to create EveBox data directory")?;

        if find_evebox_exe(&install_dir)?.is_some() {
            if !upgrade {
                info!("EveBox is already installed in the evectl-managed directory.");
                return Ok(());
            }

            remove_existing_evebox_installation()?;
        }

        std::fs::create_dir_all(&install_dir)
            .context("Failed to ensure EveBox install directory after upgrade cleanup")?;

        let temp_dir = tempfile::tempdir()?;
        let zip_path = temp_dir
            .path()
            .join(format!("evebox-{}-windows-x64.zip", EVEBOX_VERSION));

        download_file(url, &zip_path, "EveBox")?;

        info!("Extracting EveBox to {:?}", install_dir);

        let zip_file =
            std::fs::File::open(&zip_path).context("Failed to open downloaded EveBox zip file")?;
        let mut archive =
            zip::ZipArchive::new(zip_file).context("Failed to read EveBox zip archive")?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = install_dir.join(file.mangled_name());

            if file.name().ends_with('/') {
                std::fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent()
                    && !p.exists()
                {
                    std::fs::create_dir_all(p)?;
                }
                let mut outfile = std::fs::File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }

        let _ = get_evebox_exe_path()?;
        let marker_path = get_evebox_version_marker_path()?;
        std::fs::write(&marker_path, EVEBOX_VERSION).context(format!(
            "Failed to write EveBox version marker {}",
            marker_path.display()
        ))?;
        info!(
            "EveBox {} installed successfully at {:?}",
            EVEBOX_VERSION, install_dir
        );

        Ok(())
    }

    #[cfg(windows)]
    fn list_interfaces() -> Result<()> {
        println!("{:<32} {:<39} GUID", "Name", "IP Address");
        for interface in get_windows_interfaces()? {
            let ip_address = if interface.ip_address.is_empty() {
                "<no IP>"
            } else {
                &interface.ip_address
            };
            println!(
                "{:<32} {:<39} {}",
                interface.name, ip_address, interface.guid
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn build_suricata_command(guid: &str) -> Result<Command> {
        if !is_suricata_installed() {
            bail!("Suricata is not installed. Please install it first using 'evectl install'");
        }

        let suricata_path = find_suricata_executable()
            .ok_or_else(|| anyhow!("Suricata executable not found in expected locations"))?;
        let suricata_dir = suricata_path
            .parent()
            .ok_or_else(|| anyhow!("Failed to determine Suricata installation directory"))?
            .to_path_buf();

        let suricata_log_dir = get_suricata_log_dir()?;
        ensure_dir(&suricata_log_dir)?;
        let threshold_config = ensure_suricata_threshold_config()?;

        let npcap_device = format!("\\Device\\NPF_{{{}}}", guid.trim_matches(['{', '}']));
        let rules_include_path = write_suricata_rules_include_stub()?;

        let mut command = Command::new(&suricata_path);
        let suricata_config = suricata_dir.join("suricata.yaml");
        if suricata_config.exists() {
            command.arg("-c");
            command.arg(&suricata_config);
        }
        command.arg("--include");
        command.arg(&rules_include_path);
        command.current_dir(&suricata_dir);
        command.arg("-i");
        command.arg(&npcap_device);
        command.arg("-l");
        command.arg(&suricata_log_dir);
        command.arg("--set");
        command.arg(format!("threshold-file={}", threshold_config.display()));

        if let Some(classification_file) =
            find_suricata_install_file(&suricata_dir, "classification.config")
        {
            command.arg("--set");
            command.arg(format!(
                "classification-file={}",
                classification_file.display()
            ));
        } else {
            warn!(
                "Could not find classification.config under {}; relying on Suricata defaults",
                suricata_dir.display()
            );
        }

        if let Some(reference_config_file) =
            find_suricata_install_file(&suricata_dir, "reference.config")
        {
            command.arg("--set");
            command.arg(format!(
                "reference-config-file={}",
                reference_config_file.display()
            ));
        } else {
            warn!(
                "Could not find reference.config under {}; relying on Suricata defaults",
                suricata_dir.display()
            );
        }

        let config = load_evectl_config()?;

        if let Some(sensor_name) = &config.suricata.sensor_name {
            command.arg("--set");
            command.arg(format!("sensor-name={}", sensor_name));
        }

        // The BPF filter is a trailing positional argument.
        if let Some(bpf) = &config.suricata.bpf {
            command.arg(bpf);
        }

        Ok(command)
    }

    #[cfg(windows)]
    fn process_line_reader<R: std::io::Read + Send + 'static>(output: R, label: &'static str) {
        let reader = BufReader::new(output).lines();
        for line in reader {
            match line {
                Ok(line) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = writeln!(&mut stdout, "{}: {}", label, line);
                    let _ = stdout.flush();
                }
                Err(err) => {
                    debug!("Failed to read {} output: {}", label, err);
                    break;
                }
            }
        }
    }

    #[cfg(windows)]
    fn process_output_handler(child: &mut Child, label: &'static str) {
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || process_line_reader(stdout, label));
        }

        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || process_line_reader(stderr, label));
        }
    }

    #[cfg(windows)]
    fn ensure_suricata_start_allowed() -> Result<()> {
        if managed_process_is_running(ROLE_SURICATA)? {
            bail!("A managed Suricata process is already running. Use 'evectl stop' first.");
        }

        let process_count = count_named_processes("suricata")?;
        if process_count > 0 {
            bail!(
                "Suricata is already running ({} process(es) found). Stop the external Suricata process or service first.",
                process_count
            );
        }

        Ok(())
    }

    /// Pre-flight check used before starting any EveBox process. The
    /// per-role checks in the start functions are skipped here so a
    /// server and an agent can be started in sequence.
    #[cfg(windows)]
    fn ensure_evebox_start_allowed() -> Result<()> {
        if managed_process_is_running(ROLE_EVEBOX)?
            || managed_process_is_running(ROLE_EVEBOX_AGENT)?
        {
            bail!("A managed EveBox process is already running. Use 'evectl stop' first.");
        }

        let process_count = count_named_processes("evebox")?;
        if process_count > 0 {
            bail!(
                "EveBox is already running ({} process(es) found). Use 'evectl stop' first.",
                process_count
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn start_stack_foreground(guid: Option<String>) -> Result<()> {
        fn stop_children(children: &mut Vec<(&'static str, Child)>) {
            for (_, child) in children.iter() {
                let _ = stop_pid(child.id());
            }
            for (_, child) in children.iter_mut() {
                let _ = child.wait();
            }
        }

        fn spawn_foreground(
            mut command: Command,
            role: &'static str,
            children: &mut Vec<(&'static str, Child)>,
        ) -> Result<u32> {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            info!("Running command: {}", format_command_line(&command));
            let mut child = command
                .spawn()
                .context(format!("Failed to start {}", role))?;
            process_output_handler(&mut child, role);
            let pid = child.id();
            children.push((role, child));
            Ok(pid)
        }

        let config = load_evectl_config()?;
        let use_suricata = config.suricata.enabled;
        let use_server = config.evebox_server.enabled;
        let use_agent = config.evebox_agent.enabled;

        if !use_suricata && !use_server && !use_agent {
            bail!("No services are enabled. Run 'evectl install' first.");
        }

        if use_suricata {
            ensure_suricata_start_allowed()?;
        }
        if use_server || use_agent {
            ensure_evebox_start_allowed()?;
            let _ = get_evebox_exe_path()?;
        }

        ensure_ctrlc_handler()?;
        CTRL_C_RECEIVED.store(false, Ordering::SeqCst);

        let mut children: Vec<(&'static str, Child)> = vec![];

        let startup = (|| -> Result<()> {
            if use_suricata {
                let guid = resolve_interface_guid(guid, true)?;
                let command = build_suricata_command(&guid)?;
                let suricata_exe = PathBuf::from(command.get_program());
                let pid = spawn_foreground(command, ROLE_SURICATA, &mut children)?;
                wait_for_suricata_pid_readiness(pid, &suricata_exe)?;
            }

            if use_server {
                spawn_foreground(build_evebox_command()?, ROLE_EVEBOX, &mut children)?;
            }

            if use_agent {
                spawn_foreground(
                    build_evebox_agent_command()?,
                    ROLE_EVEBOX_AGENT,
                    &mut children,
                )?;
            }

            Ok(())
        })();

        if let Err(err) = startup {
            stop_children(&mut children);
            return Err(err);
        }

        println!("Foreground Windows stack started");
        for (role, child) in &children {
            println!("  {} PID: {}", role, child.id());
        }
        if use_server {
            println!("  EveBox URL: {}", EVEBOX_ACCESS_URL);
        }
        println!("Press Ctrl-C to stop.");

        let mut failure: Option<String> = None;
        let mut shutdown_requested = false;
        let mut statuses: Vec<Option<std::process::ExitStatus>> = vec![None; children.len()];

        loop {
            let mut request_shutdown = false;

            if !shutdown_requested && CTRL_C_RECEIVED.swap(false, Ordering::SeqCst) {
                info!("Received Ctrl-C, stopping foreground Windows stack");
                request_shutdown = true;
            }

            for (index, (role, child)) in children.iter_mut().enumerate() {
                if statuses[index].is_none()
                    && let Some(status) = child.try_wait()?
                {
                    if !shutdown_requested && !request_shutdown {
                        failure = Some(format!("{} exited with status: {}", role, status));
                        request_shutdown = true;
                    }
                    statuses[index] = Some(status);
                }
            }

            if request_shutdown && !shutdown_requested {
                shutdown_requested = true;
                for (index, (_, child)) in children.iter().enumerate() {
                    if statuses[index].is_none() {
                        let _ = stop_pid(child.id());
                    }
                }
            }

            if statuses.iter().all(|status| status.is_some()) {
                break;
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        if let Some(message) = failure {
            bail!(message);
        }

        Ok(())
    }

    #[cfg(windows)]
    fn start_suricata_background(guid: &str) -> Result<RuntimeMetadata> {
        ensure_suricata_start_allowed()?;

        let command = build_suricata_command(guid)?;
        info!("Running command: {}", format_command_line(&command));
        let pid = spawn_detached(&command)?;

        let command = build_suricata_command(guid)?;
        let metadata = build_runtime_metadata(ROLE_SURICATA, &command, pid, None, None)?;

        ensure_dir(&get_suricata_run_dir()?)?;
        write_pid(&get_suricata_pid_path()?, pid)?;
        write_runtime_metadata(&get_suricata_runtime_path()?, &metadata)?;

        Ok(metadata)
    }

    #[cfg(windows)]
    fn build_evebox_command() -> Result<Command> {
        let evebox_exe = get_evebox_exe_path()?;

        let evebox_root_dir = get_evebox_root_dir()?;
        let evebox_data_dir = get_evebox_data_dir()?;
        ensure_dir(&evebox_root_dir)?;
        ensure_dir(&evebox_data_dir)?;

        let mut command = Command::new(&evebox_exe);
        command.current_dir(&evebox_data_dir);
        command.arg("server");
        command.arg("--sqlite");
        command.arg("--no-auth");
        command.arg("--no-tls");
        command.arg("--host");
        command.arg(EVEBOX_HOST);
        command.arg("--port");
        command.arg(EVEBOX_PORT);
        command.arg("-D");
        command.arg(&evebox_data_dir);
        command.arg(get_suricata_eve_json_path()?);

        Ok(command)
    }

    #[cfg(windows)]
    fn start_evebox_background() -> Result<RuntimeMetadata> {
        if managed_process_is_running(ROLE_EVEBOX)? {
            bail!("A managed EveBox server is already running. Use 'evectl stop' first.");
        }

        let command = build_evebox_command()?;
        info!("Running command: {}", format_command_line(&command));
        let pid = spawn_detached(&command)?;

        let command = build_evebox_command()?;
        let metadata = build_runtime_metadata(ROLE_EVEBOX, &command, pid, None, None)?;

        write_pid(&get_evebox_pid_path()?, pid)?;
        write_runtime_metadata(&get_evebox_runtime_path()?, &metadata)?;

        Ok(metadata)
    }

    /// Write the EveBox agent input configuration with Windows paths.
    /// Forward slashes keep the YAML free of escape issues.
    #[cfg(windows)]
    fn write_evebox_agent_config() -> Result<PathBuf> {
        fn yaml_path(path: &Path) -> String {
            path.to_string_lossy().replace('\\', "/")
        }

        let agent_dir = get_evebox_agent_dir()?;
        let data_dir = get_evebox_agent_data_dir()?;
        ensure_dir(&data_dir)?;

        let config_path = agent_dir.join("evectl-input.yaml");
        let contents = format!(
            "# Generated by evectl. Do not edit.\ndata-directory: \"{}\"\ninput:\n  paths:\n    - \"{}\"\n",
            yaml_path(&data_dir),
            yaml_path(&get_suricata_eve_json_path()?)
        );

        std::fs::write(&config_path, contents).context(format!(
            "Failed to write EveBox agent configuration {}",
            config_path.display()
        ))?;

        Ok(config_path)
    }

    #[cfg(windows)]
    fn build_evebox_agent_command() -> Result<Command> {
        let config = load_evectl_config()?;
        if config.evebox_agent.server.trim().is_empty() {
            bail!("The EveBox agent server URL is not configured");
        }

        let evebox_exe = get_evebox_exe_path()?;
        let agent_dir = get_evebox_agent_dir()?;
        ensure_dir(&agent_dir)?;
        let config_path = write_evebox_agent_config()?;

        let mut command = Command::new(&evebox_exe);
        command.current_dir(&agent_dir);
        command.arg("agent");
        command.arg("--config");
        command.arg(&config_path);
        command.arg("--server");
        command.arg(&config.evebox_agent.server);
        if config.evebox_agent.disable_certificate_validation {
            command.arg("--disable-certificate-check");
        }

        Ok(command)
    }

    #[cfg(windows)]
    fn start_evebox_agent_background() -> Result<RuntimeMetadata> {
        if managed_process_is_running(ROLE_EVEBOX_AGENT)? {
            bail!("A managed EveBox agent is already running. Use 'evectl stop' first.");
        }

        let command = build_evebox_agent_command()?;
        info!("Running command: {}", format_command_line(&command));
        let pid = spawn_detached(&command)?;

        let command = build_evebox_agent_command()?;
        let metadata = build_runtime_metadata(ROLE_EVEBOX_AGENT, &command, pid, None, None)?;

        write_pid(&get_evebox_agent_pid_path()?, pid)?;
        write_runtime_metadata(&get_evebox_agent_runtime_path()?, &metadata)?;

        Ok(metadata)
    }

    #[cfg(windows)]
    fn wait_for_suricata_pid_readiness(pid: u32, exe_path: &Path) -> Result<()> {
        let eve_json = get_suricata_eve_json_path()?;
        let started = std::time::Instant::now();

        while started.elapsed() < SURICATA_READY_TIMEOUT {
            if !is_pid_running(pid) {
                bail!("Suricata exited before EveBox could be started");
            }

            if process_matches_exe(pid, exe_path)? && eve_json.exists() {
                return Ok(());
            }

            std::thread::sleep(Duration::from_millis(250));
        }

        if !is_pid_running(pid) {
            bail!("Suricata exited before it became ready");
        }

        Ok(())
    }

    #[cfg(windows)]
    fn wait_for_suricata_readiness(metadata: &RuntimeMetadata) -> Result<()> {
        wait_for_suricata_pid_readiness(metadata.pid, Path::new(&metadata.exe_path))
    }

    #[cfg(windows)]
    fn validate_background_process_started(metadata: &RuntimeMetadata) -> Result<()> {
        std::thread::sleep(EVEBOX_STARTUP_GRACE_PERIOD);

        if !is_pid_running(metadata.pid) {
            bail!("{} exited immediately after startup", metadata.role);
        }

        if !process_matches_exe(metadata.pid, Path::new(&metadata.exe_path))? {
            bail!(
                "{} PID {} no longer matches {}",
                metadata.role,
                metadata.pid,
                metadata.exe_path
            );
        }

        Ok(())
    }

    #[cfg(windows)]
    fn stop_evebox_managed() -> Result<()> {
        stop_managed_process(ROLE_EVEBOX)
    }

    #[cfg(windows)]
    fn stop_evebox_agent_managed() -> Result<()> {
        stop_managed_process(ROLE_EVEBOX_AGENT)
    }

    #[cfg(windows)]
    fn stop_suricata_managed() -> Result<()> {
        stop_managed_process(ROLE_SURICATA)
    }

    #[cfg(windows)]
    fn start_stack(debug: bool, guid: Option<String>) -> Result<()> {
        if debug {
            return start_stack_foreground(guid);
        }

        let config = load_evectl_config()?;
        let use_suricata = config.suricata.enabled;
        let use_server = config.evebox_server.enabled;
        let use_agent = config.evebox_agent.enabled;

        if !use_suricata && !use_server && !use_agent {
            bail!("No services are enabled. Run 'evectl install' first.");
        }

        if managed_process_is_running(ROLE_SURICATA)?
            || managed_process_is_running(ROLE_EVEBOX)?
            || managed_process_is_running(ROLE_EVEBOX_AGENT)?
        {
            bail!("The Windows-managed stack is already running. Use 'evectl stop' first.");
        }

        if use_server || use_agent {
            ensure_evebox_start_allowed()?;
            let _ = get_evebox_exe_path()?;
        }

        let result = (|| -> Result<Vec<RuntimeMetadata>> {
            let mut started = vec![];

            if use_suricata {
                let guid = resolve_interface_guid(guid, true)?;
                let suricata = start_suricata_background(&guid)?;
                wait_for_suricata_readiness(&suricata)?;
                started.push(suricata);
            }

            if use_server {
                let evebox = start_evebox_background()?;
                validate_background_process_started(&evebox)?;
                started.push(evebox);
            }

            if use_agent {
                let agent = start_evebox_agent_background()?;
                validate_background_process_started(&agent)?;
                started.push(agent);
            }

            Ok(started)
        })();

        let started = match result {
            Ok(started) => started,
            Err(err) => {
                let _ = stop_stack();
                return Err(err);
            }
        };

        println!("Windows stack started in background");
        for metadata in &started {
            println!("  {} PID: {}", metadata.role, metadata.pid);
        }
        if use_suricata {
            println!("  Suricata log: {}", get_suricata_log_dir()?.display());
        }
        if use_server {
            println!("  EveBox data:  {}", get_evebox_data_dir()?.display());
            println!("  EveBox URL:   {}", EVEBOX_ACCESS_URL);
        }

        Ok(())
    }

    /// Restart the stack, preferring the interface the running Suricata
    /// was started with (e.g. a --guid override) over the saved config.
    #[cfg(windows)]
    fn restart_stack() -> Result<()> {
        let guid = capture_restart_plan()?.suricata_guid;
        stop_stack()?;
        start_stack(false, guid)
    }

    #[cfg(windows)]
    fn stop_stack() -> Result<()> {
        let mut errors = vec![];

        if let Err(err) = stop_evebox_agent_managed() {
            errors.push(format!("Failed to stop EveBox agent: {err}"));
        }

        if let Err(err) = stop_evebox_managed() {
            errors.push(format!("Failed to stop EveBox: {err}"));
        }

        if let Err(err) = stop_suricata_managed() {
            errors.push(format!("Failed to stop Suricata: {err}"));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("{}", errors.join("\n"))
        }
    }

    #[cfg(windows)]
    fn format_command_line(command: &std::process::Command) -> String {
        fn quote(arg: &str) -> String {
            if arg.contains([' ', '\t', '"']) {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg.to_string()
            }
        }

        let mut parts = vec![quote(&command.get_program().to_string_lossy())];
        for arg in command.get_args() {
            parts.push(quote(&arg.to_string_lossy()));
        }
        parts.join(" ")
    }

    #[cfg(windows)]
    fn ensure_ctrlc_handler() -> Result<()> {
        let result = CTRL_C_HANDLER_SETUP.get_or_init(|| {
            ctrlc::set_handler(|| {
                CTRL_C_RECEIVED.store(true, Ordering::SeqCst);
            })
            .map_err(|err| err.to_string())
        });

        match result {
            Ok(()) => Ok(()),
            Err(err) => bail!("Failed to set Ctrl-C handler: {}", err),
        }
    }

    #[cfg(windows)]
    fn get_windows_interfaces() -> Result<Vec<WindowsInterface>> {
        use std::io;
        use std::net::{Ipv4Addr, Ipv6Addr};
        use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR, WIN32_ERROR};
        use windows::Win32::NetworkManagement::IpHelper::{
            ConvertInterfaceLuidToGuid, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses,
            IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
        };
        use windows::core::GUID;

        fn win32_error_message(code: WIN32_ERROR) -> String {
            io::Error::from_raw_os_error(code.0 as i32).to_string()
        }

        fn adapter_guid(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Result<String> {
            if !adapter.AdapterName.is_null()
                && let Ok(name) = unsafe { adapter.AdapterName.to_string() }
                && let Some(guid) = normalize_interface_guid(&name)
            {
                return Ok(guid);
            }

            let mut guid = GUID::zeroed();
            let status = unsafe { ConvertInterfaceLuidToGuid(&adapter.Luid, &mut guid) };
            if status == NO_ERROR {
                Ok(format!("{guid:?}"))
            } else {
                bail!(
                    "Failed to resolve interface GUID: {}",
                    win32_error_message(status)
                )
            }
        }

        fn socket_address_to_string(
            address: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS,
        ) -> Option<(String, bool)> {
            if address.lpSockaddr.is_null() {
                return None;
            }

            let family = unsafe { (*address.lpSockaddr).sa_family };
            if family == AF_INET {
                let sockaddr = unsafe { &*(address.lpSockaddr as *const SOCKADDR_IN) };
                let ip: Ipv4Addr = sockaddr.sin_addr.into();
                Some((ip.to_string(), true))
            } else if family == AF_INET6 {
                let sockaddr = unsafe { &*(address.lpSockaddr as *const SOCKADDR_IN6) };
                let ip: Ipv6Addr = sockaddr.sin6_addr.into();
                Some((ip.to_string(), false))
            } else {
                None
            }
        }

        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
            GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_SKIP_DNS_SERVER.0,
        );
        let mut buffer_size = 16 * 1024;
        let mut result = BTreeMap::new();

        for _ in 0..3 {
            let mut buffer = vec![0u8; buffer_size as usize];
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    flags,
                    None,
                    Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                    &mut buffer_size,
                )
            };

            if status == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }

            if status != NO_ERROR.0 {
                bail!(
                    "GetAdaptersAddresses failed: {}",
                    win32_error_message(WIN32_ERROR(status))
                );
            }

            let mut current = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            while !current.is_null() {
                let adapter = unsafe { &*current };
                current = adapter.Next;

                if adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                    continue;
                }

                let name = if adapter.FriendlyName.is_null() {
                    String::new()
                } else {
                    unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default()
                };
                let name = if name.is_empty() {
                    if adapter.AdapterName.is_null() {
                        "<unnamed>".to_string()
                    } else {
                        unsafe { adapter.AdapterName.to_string() }
                            .unwrap_or_else(|_| "<unnamed>".to_string())
                    }
                } else {
                    name
                };

                let guid = match adapter_guid(adapter) {
                    Ok(guid) => guid,
                    Err(err) => {
                        warn!("Skipping network interface '{}': {}", name, err);
                        continue;
                    }
                };

                let mut ip_address = String::new();
                let mut unicast = adapter.FirstUnicastAddress;
                while !unicast.is_null() {
                    let address = unsafe { &*unicast };
                    if let Some((candidate, is_ipv4)) = socket_address_to_string(&address.Address) {
                        if is_ipv4 {
                            ip_address = candidate;
                            break;
                        }
                        if ip_address.is_empty() {
                            ip_address = candidate;
                        }
                    }
                    unicast = address.Next;
                }

                result
                    .entry(guid.clone())
                    .or_insert_with(|| WindowsInterface {
                        name,
                        ip_address,
                        guid,
                    });
            }

            let mut interfaces: Vec<_> = result.into_values().collect();
            interfaces.sort_by(|a, b| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
                    .then(a.guid.cmp(&b.guid))
            });
            return Ok(interfaces);
        }

        bail!("GetAdaptersAddresses failed after repeated buffer resizing")
    }

    #[derive(Debug, Clone)]
    struct WindowsInterface {
        name: String,
        ip_address: String,
        guid: String,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rules_digest_tracks_content_changes() {
            let dir = tempfile::tempdir().unwrap();
            let rules_dir = dir.path().join("rules");
            assert_eq!(rules_digest(&rules_dir).unwrap(), None);

            std::fs::create_dir_all(rules_dir.join("datasets")).unwrap();
            std::fs::write(
                rules_dir.join("suricata.rules"),
                "alert ip any any -> any any (sid:1;)\n",
            )
            .unwrap();
            std::fs::write(rules_dir.join("datasets").join("a.lst"), "one\n").unwrap();
            let first = rules_digest(&rules_dir).unwrap();
            assert!(first.is_some());

            // Rewriting identical content is not a change.
            std::fs::write(
                rules_dir.join("suricata.rules"),
                "alert ip any any -> any any (sid:1;)\n",
            )
            .unwrap();
            assert_eq!(rules_digest(&rules_dir).unwrap(), first);

            // A dataset change counts, as does a rules change.
            std::fs::write(rules_dir.join("datasets").join("a.lst"), "two\n").unwrap();
            let second = rules_digest(&rules_dir).unwrap();
            assert_ne!(second, first);
            std::fs::write(rules_dir.join("suricata.rules"), "").unwrap();
            assert_ne!(rules_digest(&rules_dir).unwrap(), second);
        }

        #[test]
        fn command_is_optional_for_interactive_menu() {
            let args = Args::try_parse_from(["evectl"]).expect("parse args");
            assert!(args.command.is_none());
        }

        #[test]
        fn explicit_commands_still_parse() {
            let args = Args::try_parse_from(["evectl", "start", "--debug"]).expect("parse args");
            assert!(matches!(
                args.command,
                Some(Commands::Start {
                    debug: true,
                    guid: None
                })
            ));
        }

        #[test]
        fn update_command_parses_with_aliases() {
            for name in ["update", "upgrade", "upgrade-suricata"] {
                let args = Args::try_parse_from(["evectl", name]).expect("parse args");
                assert!(matches!(args.command, Some(Commands::Update)));
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use clap::Parser;

    #[derive(Parser, Debug, Clone)]
    pub(crate) struct Args;
}

#[cfg(not(windows))]
pub(crate) use imp::Args;
#[cfg(windows)]
pub(crate) use imp::{Args, Commands, main};
