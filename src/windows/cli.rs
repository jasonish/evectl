// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Windows command line and dispatch.

use crate::config::EveBoxChannel;
use clap::{Parser, Subcommand};

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

    /// Internal filestore retention worker; launched and stopped with the stack.
    #[command(hide = true)]
    Housekeep {
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        retention_days: u32,
    },

    /// Stop the Suricata and EveBox stack.
    Stop,

    /// Stop and start the Suricata and EveBox stack.
    Restart,

    /// Display status of each service.
    Status,

    /// Update Suricata rules.
    UpdateRules,

    /// Update EveCtl, bundled Windows components, and EveBox from the selected release channel.
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

    /// Select the EveBox release channel; run update to apply it to an existing installation.
    #[command(name = "set-evebox-channel")]
    SetEveBoxChannel {
        /// Omit to choose interactively. Applies to both server and agent.
        #[arg(value_enum)]
        channel: Option<EveBoxChannel>,
    },
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
#[cfg(windows)]
pub(crate) fn main(args: Args) -> anyhow::Result<()> {
    use super::install::{add_shortcuts, install, upgrade_windows_components};
    use super::interfaces::{config_set_interface, list_interfaces};
    use super::menu::{config_set_evebox_channel, log_status, menu_main, project_info};
    use super::paths::{Paths, load_evectl_config};
    use super::rules::{
        disable_ruleset, enable_ruleset, list_enabled_rulesets, update_rules, update_sources,
    };
    use super::stack::windows_status;
    use super::stack::{restart_stack, run_housekeeper, start_stack, stop_stack};
    use super::uninstall::uninstall;

    let paths = Paths::discover()?;
    match args.command {
        Some(Commands::Start { debug, guid }) => start_stack(&paths, debug, guid),
        Some(Commands::Housekeep { retention_days }) => run_housekeeper(&paths, retention_days),
        Some(Commands::Stop) => stop_stack(&paths),
        Some(Commands::Restart) => restart_stack(&paths),
        Some(Commands::Status) => {
            let config = load_evectl_config(&paths)?;
            log_status(windows_status(&paths, &config)?, &config);
            Ok(())
        }
        Some(Commands::UpdateRules) => update_rules(&paths, false, false),
        Some(Commands::Update) => upgrade_windows_components(&paths).map(|_| ()),
        Some(Commands::Version) => {
            println!("{}", env!("EVECTL_VERSION"));
            Ok(())
        }
        Some(Commands::Info) => project_info(&paths),
        Some(Commands::Install) => install(&paths),
        Some(Commands::Uninstall { config, all, yes }) => uninstall(&paths, config, all, yes),
        Some(Commands::ListInterfaces) => list_interfaces(),
        Some(Commands::AddShortcuts) => add_shortcuts(&paths),
        Some(Commands::Config { command }) => match command {
            ConfigCommands::SetInterface => config_set_interface(&paths),
            ConfigCommands::SetEveBoxChannel { channel } => {
                config_set_evebox_channel(&paths, channel)
            }
        },
        Some(Commands::Rules { command }) => match command {
            RulesCommands::Update { force, quiet } => update_rules(&paths, force, quiet),
            RulesCommands::UpdateSources => update_sources(&paths),
            RulesCommands::EnableRuleset { name } => enable_ruleset(&paths, name.as_deref()),
            RulesCommands::DisableRuleset { name } => disable_ruleset(&paths, &name),
            RulesCommands::ListEnabledRulesets => list_enabled_rulesets(&paths),
        },
        None => menu_main(&paths),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evebox_channel_command_parses_choices_and_optional_prompt() {
        for (name, expected) in [
            ("release", EveBoxChannel::Release),
            ("development", EveBoxChannel::Development),
            ("devel", EveBoxChannel::Development),
        ] {
            let args =
                Args::try_parse_from(["evectl", "config", "set-evebox-channel", name]).unwrap();
            assert!(matches!(args.command,
                Some(Commands::Config { command: ConfigCommands::SetEveBoxChannel { channel: Some(channel) } })
                if channel == expected
            ));
        }
        let args = Args::try_parse_from(["evectl", "config", "set-evebox-channel"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Config {
                command: ConfigCommands::SetEveBoxChannel { channel: None }
            })
        ));
        assert!(
            Args::try_parse_from(["evectl", "config", "set-evebox-channel", "unknown"]).is_err()
        );
    }

    #[test]
    fn housekeeper_command_requires_positive_retention_and_is_hidden() {
        let args = Args::try_parse_from(["evectl", "housekeep", "--retention-days", "7"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Housekeep { retention_days: 7 })
        ));
        assert!(Args::try_parse_from(["evectl", "housekeep", "--retention-days", "0"]).is_err());
        assert!(Args::try_parse_from(["evectl", "housekeep"]).is_err());
        use clap::CommandFactory;
        let help = Args::command().render_long_help().to_string();
        assert!(!help.contains("housekeep"));
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
