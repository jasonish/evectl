// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Windows full packet capture: a Suricata spool served through EveBox.

use std::path::Path;
use std::process::Command;

use crate::config::FpcConfig;
use crate::prelude::*;

#[cfg(windows)]
pub(super) fn menu(config: &mut Config, spool: &Path) -> Result<()> {
    #[derive(Clone)]
    enum Options {
        Toggle,
        MaxFiles,
        Return,
    }

    loop {
        crate::term::clear();
        println!("Packet captures: {}", spool.display());
        println!("Captures are available through the EveBox server or agent.");
        println!("Changes take effect after restarting services.");

        let mut selections = crate::prompt::Selections::new();
        selections.push(
            Options::Toggle,
            if config.fpc.enabled {
                "Disable Full Packet Capture"
            } else {
                "Enable Full Packet Capture"
            },
        );
        let threads = FpcConfig::capture_threads();
        selections.push(
            Options::MaxFiles,
            format!(
                "Retention (current: {} x {} files, ~{}; {} per capture thread x {} threads)",
                config.fpc.effective_max_files_for(threads),
                FpcConfig::FILE_SIZE,
                config.fpc.disk_usage_for(threads),
                config.fpc.max_files_per_thread(threads),
                threads,
            ),
        );
        selections.push(Options::Return, "Return");

        match inquire::Select::new("EveCtl: Configure Full Packet Capture", selections.to_vec())
            .prompt()
        {
            Ok(selection) => match selection.tag {
                Options::Toggle => {
                    if config.fpc.enabled {
                        config.fpc.enabled = false;
                        info!("Existing packet captures remain in {}", spool.display());
                        crate::prompt::enter();
                    } else if !config.suricata.enabled
                        || !(config.evebox_server.enabled || config.evebox_agent.enabled)
                    {
                        error!(
                            "Full packet capture requires Suricata and either the EveBox server or agent"
                        );
                        crate::prompt::enter();
                    } else {
                        if config.evebox_agent.enabled
                            && !crate::menu::evebox_agent::setup_retrieval(config)
                        {
                            continue;
                        }
                        let message = format!(
                            "Enable full packet capture (up to ~{})?",
                            config.fpc.disk_usage_for(threads)
                        );
                        if inquire::Confirm::new(&message)
                            .with_default(false)
                            .prompt()
                            .unwrap_or(false)
                        {
                            config.fpc.enabled = true;
                        }
                    }
                }
                Options::MaxFiles => {
                    let prompt = format!(
                        "Maximum total number of {} pcap files to retain (across all capture threads):",
                        FpcConfig::FILE_SIZE
                    );
                    let help = format!(
                        "Rounded down to a multiple of {threads} capture threads (minimum {threads})"
                    );
                    let validator = move |input: &str| {
                        Ok(match input.trim().parse::<u32>() {
                            Ok(n) if n as usize >= threads => inquire::validator::Validation::Valid,
                            Ok(_) => inquire::validator::Validation::Invalid(
                                format!("Must be at least {threads}, one file per capture thread")
                                    .into(),
                            ),
                            Err(_) => inquire::validator::Validation::Invalid(
                                "Must be a positive number".into(),
                            ),
                        })
                    };
                    if let Ok(value) = inquire::Text::new(&prompt)
                        .with_default(&config.fpc.max_files().to_string())
                        .with_help_message(&help)
                        .with_validator(validator)
                        .prompt()
                        && let Ok(n) = value.trim().parse::<u32>()
                    {
                        config.fpc.max_files = if n == FpcConfig::DEFAULT_MAX_FILES {
                            None
                        } else {
                            Some(n)
                        };
                    }
                }
                Options::Return => break,
            },
            Err(_) => break,
        }
    }

    Ok(())
}

/// Capture only when a local EveBox service can serve the spool.
pub(super) fn effective_config(config: &Config) -> FpcConfig {
    FpcConfig {
        enabled: config.fpc.enabled
            && config.suricata.enabled
            && (config.evebox_server.enabled || config.evebox_agent.enabled),
        ..config.fpc.clone()
    }
}

pub(super) fn configure_evebox_command(command: &mut Command, config: &Config, spool: &Path) {
    if effective_config(config).enabled {
        command.arg("--pcap-directory").arg(spool);
        command.arg("--pcap-prefix=log.");
    }
}

pub(super) fn configure_agent_command(command: &mut Command, config: &Config, spool: &Path) {
    if let Some(agent_id) = &config.evebox_agent.agent_id {
        command.arg("--agent-id").arg(agent_id);
    }
    configure_evebox_command(command, config, spool);
    if effective_config(config).enabled {
        match &config.evebox_agent.key {
            Some(key) => {
                // Keep the key out of command logs and runtime metadata.
                command.env("EVEBOX_SERVER_KEY", key);
            }
            None => warn!(
                "Packet retrieval is enabled but no agent key is set; the EveBox server \
                 will reject the retrieval channel unless it allows unauthenticated agents"
            ),
        }
    }
}

/// Find pcap-log outputs by name rather than assuming an index in the
/// installed Suricata configuration. Leave all other outputs untouched.
pub(super) fn configure_command(
    command: &mut Command,
    dump: &str,
    fpc: &FpcConfig,
    spool: &Path,
) -> Result<()> {
    let pattern = regex::Regex::new(r"^(outputs\.\d+) = pcap-log$")?;
    let paths: Vec<String> = dump
        .lines()
        .filter_map(|line| pattern.captures(line.trim()))
        .map(|c| format!("{}.pcap-log", &c[1]))
        .collect();
    if fpc.enabled && paths.is_empty() {
        bail!("full packet capture enabled but Suricata has no pcap-log output");
    }

    for path in paths {
        command.arg("--set");
        command.arg(format!("{path}.enabled={}", fpc.enabled));
        if !fpc.enabled {
            continue;
        }

        // Multi mode writes a separate spool per packet-processing thread.
        // Suricata enforces max-files per thread, so divide the total cap.
        for (key, value) in [
            ("mode", "multi".to_string()),
            ("dir", spool.to_string_lossy().replace('\\', "/")),
            ("filename", "log.%n.%t.pcap".to_string()),
            ("limit", FpcConfig::FILE_SIZE.to_string()),
            (
                "max-files",
                fpc.max_files_per_thread(FpcConfig::capture_threads())
                    .to_string(),
            ),
            ("compression", "none".to_string()),
            ("use-stream-depth", "no".to_string()),
            ("honor-pass-rules", "no".to_string()),
        ] {
            command.arg("--set");
            command.arg(format!("{path}.{key}={value}"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn evebox_capture_requires_suricata_and_a_retrieval_service() {
        let spool = Path::new(r"C:\Users\Test User\suricata\log\pcap");
        for suricata in [false, true] {
            for server in [false, true] {
                for agent in [false, true] {
                    for capture in [false, true] {
                        let mut config = Config::default();
                        config.suricata.enabled = suricata;
                        config.evebox_server.enabled = server;
                        config.evebox_agent.enabled = agent;
                        config.evebox_agent.agent_id = Some("sensor".into());
                        config.evebox_agent.key = Some("secret-key".into());
                        config.fpc.enabled = capture;
                        config.fpc.max_files = Some(20);
                        let enabled = suricata && capture && (server || agent);
                        let effective = effective_config(&config);
                        assert_eq!(effective.enabled, enabled);
                        assert_eq!(effective.max_files, Some(20));

                        let mut server_command = Command::new("evebox.exe");
                        configure_evebox_command(&mut server_command, &config, spool);
                        let expected = if enabled {
                            vec![
                                "--pcap-directory",
                                spool.to_str().unwrap(),
                                "--pcap-prefix=log.",
                            ]
                        } else {
                            vec![]
                        };
                        assert_eq!(args(&server_command), expected);
                        assert_eq!(server_command.get_envs().count(), 0);

                        let mut agent_command = Command::new("evebox.exe");
                        configure_agent_command(&mut agent_command, &config, spool);
                        let mut expected_agent = vec!["--agent-id", "sensor"];
                        expected_agent.extend(expected);
                        assert_eq!(args(&agent_command), expected_agent);
                        let key = agent_command
                            .get_envs()
                            .find(|(name, _)| *name == "EVEBOX_SERVER_KEY");
                        assert_eq!(key.is_some(), enabled);
                        if let Some((_, value)) = key {
                            assert_eq!(value, Some(std::ffi::OsStr::new("secret-key")));
                        }
                        assert!(
                            !args(&agent_command)
                                .iter()
                                .any(|arg| arg.contains("secret-key"))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn agent_without_credentials_keeps_capture_and_default_identity() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.evebox_agent.enabled = true;
        config.fpc.enabled = true;
        let mut command = Command::new("evebox.exe");
        configure_agent_command(&mut command, &config, Path::new("pcap"));
        assert_eq!(
            args(&command),
            ["--pcap-directory", "pcap", "--pcap-prefix=log."]
        );
        assert_eq!(command.get_envs().count(), 0);
    }

    #[test]
    fn enabled_capture_configures_only_pcap_output() {
        let mut command = Command::new("suricata.exe");
        let fpc = FpcConfig {
            enabled: true,
            max_files: Some(7),
        };
        configure_command(
            &mut command,
            "outputs.0 = eve-log\noutputs.23 = pcap-log\noutputs.24 = stats\n",
            &fpc,
            Path::new(r"C:\Users\Test User\evectl\suricata\log\pcap"),
        )
        .unwrap();
        let args = args(&command);
        let max_files = format!(
            "max-files={}",
            fpc.max_files_per_thread(FpcConfig::capture_threads())
        );
        let expected = [
            "enabled=true",
            "mode=multi",
            "dir=C:/Users/Test User/evectl/suricata/log/pcap",
            "filename=log.%n.%t.pcap",
            "limit=256mb",
            max_files.as_str(),
            "compression=none",
            "use-stream-depth=no",
            "honor-pass-rules=no",
        ];
        assert_eq!(args.len(), expected.len() * 2);
        for (pair, setting) in args.as_chunks::<2>().0.iter().zip(expected) {
            assert_eq!(pair[0], "--set");
            assert_eq!(pair[1], format!("outputs.23.pcap-log.{setting}"));
        }
    }

    #[test]
    fn disabled_capture_overrides_installed_config() {
        let mut command = Command::new("suricata.exe");
        configure_command(
            &mut command,
            "outputs.3 = pcap-log\noutputs.3.pcap-log.enabled = yes\noutputs.10 = pcap-log\n",
            &FpcConfig::default(),
            Path::new("unused"),
        )
        .unwrap();
        assert_eq!(
            args(&command),
            [
                "--set",
                "outputs.3.pcap-log.enabled=false",
                "--set",
                "outputs.10.pcap-log.enabled=false",
            ]
        );
    }

    #[test]
    fn enabled_capture_requires_pcap_output() {
        for enabled in [false, true] {
            let mut command = Command::new("suricata.exe");
            let result = configure_command(
                &mut command,
                "outputs.0 = eve-log\nprofiling.pcap-log.enabled = no\n",
                &FpcConfig {
                    enabled,
                    max_files: None,
                },
                Path::new("pcap"),
            );
            assert_eq!(result.is_err(), enabled);
            assert!(args(&command).is_empty());
        }
    }

    #[test]
    fn retention_is_divided_across_threads_and_never_unlimited() {
        let threads = FpcConfig::capture_threads() as u32;
        for (max_files, expected) in [
            (None, (FpcConfig::DEFAULT_MAX_FILES / threads).max(1)),
            (Some(0), 1),
            (Some(1), 1),
            (Some(threads * 3), 3),
            (Some(threads * 4 - 1), 3),
        ] {
            let mut command = Command::new("suricata.exe");
            configure_command(
                &mut command,
                "outputs.5 = pcap-log\n",
                &FpcConfig {
                    enabled: true,
                    max_files,
                },
                Path::new("pcap"),
            )
            .unwrap();
            assert!(args(&command).contains(&format!("outputs.5.pcap-log.max-files={expected}")));
        }
    }
}
