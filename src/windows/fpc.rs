// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Windows full packet capture: a Suricata spool served through EveBox.

use std::path::Path;
use std::process::Command;

use crate::config::FpcConfig;
use crate::prelude::*;

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
    configure_evebox_command(command, config, spool);
    let retrieval = effective_config(config).enabled || super::file_extraction::enabled(config);
    match &config.evebox_agent.key {
        Some(key) => {
            // Keep the key out of command logs and runtime metadata.
            command.env("EVEBOX_SERVER_KEY", key);
        }
        None if retrieval => warn!(
            "File or packet retrieval is enabled but no agent key is set; the EveBox server \
             will reject the retrieval channel unless it allows unauthenticated agents"
        ),
        None => {}
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
                        assert_eq!(args(&agent_command), expected);
                        let key = agent_command
                            .get_envs()
                            .find(|(name, _)| *name == "EVEBOX_SERVER_KEY");
                        assert!(key.is_some());
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
