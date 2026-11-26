// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::Command;

use crate::configs;
use crate::container::{Container, RESTART_POLICY_ARG};
use crate::prelude::*;
use crate::suricata::{self, FILESTORE_CONTAINER_DIR, PCAP_LOG_CONTAINER_DIR, PCAP_LOG_PREFIX};

pub(crate) fn container_name(context: &Context) -> String {
    format!("{}-evebox-agent", context.container_prefix())
}

pub(crate) fn start(context: &Context) -> Result<()> {
    crate::container::start_detached(context, &container_name(context), "EveBox-Agent", || {
        build_command(context, true)
    })
}

pub(crate) fn build_command(context: &Context, detached: bool) -> Result<Command> {
    let use_socket = context.config.uses_eve_socket();
    let mut command = context.manager.command();
    command.args(["run", "--name", &container_name(context)]);
    if detached {
        command.args(["--detach", RESTART_POLICY_ARG]);
    }

    if use_socket {
        command.arg("--user=0:998");
    }

    let mut libdir = context.data_dir().join("evebox").join("agent");
    let configdir = context.config_dir().join("evebox").join("agent");
    let input_config = configdir.join("evectl-input.yaml");
    let mut volumes = Vec::new();
    if let Some(path) = context.config.agent_external_input() {
        use sha2::{Digest, Sha256};

        let (source, filename) = external_log_input(path)?;
        let root = context.root.canonicalize()?;
        if Path::new(&source).starts_with(&root) || root.starts_with(&source) {
            bail!("External EVE log directory must not overlap the EveCtl instance directory");
        }
        // --mount fails on a missing source and, unlike our instance volume
        // helper, never relabels the host directory on SELinux systems.
        command.arg(format!(
            "--mount=type=bind,src={source},dst=/external-logs,readonly"
        ));
        // EveBox keys bookmarks by container path. Isolate sources even
        // though each is mounted at the same path inside the container.
        let source_id: String = Sha256::digest(source.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        libdir = libdir.join(format!("external-{source_id}"));
        configs::write_evebox_agent_external_file_config(&input_config, filename)?;
    } else {
        let logdir = suricata::log_dir(context);
        std::fs::create_dir_all(&logdir)?;
        volumes.push(context.manager.bind_mount(&logdir, "/var/log/suricata"));
        if use_socket {
            let rundir = suricata::run_dir(context);
            std::fs::create_dir_all(&rundir)?;
            volumes.push(context.manager.bind_mount(&rundir, "/var/run/suricata"));
            configs::write_evebox_agent_socket_config(&input_config)?;
        } else {
            configs::write_evebox_agent_file_config(&input_config)?;
        }
    }
    std::fs::create_dir_all(&libdir)?;
    volumes.push(context.manager.bind_mount(&libdir, "/var/lib/evebox"));
    volumes.push(context.manager.bind_mount(&configdir, "/config"));

    for volume in volumes {
        command.arg(format!("--volume={}", volume));
    }

    // For now use host networking. We don't listen on any ports but
    // may need to connect to localhost of the host system.
    command.arg("--net=host");

    let fpc = context.config.uses_fpc();
    let file_extraction = context.config.uses_file_extraction();
    // The agent key authenticates the agent to the server and its name is
    // the agent's identity, stamped on submitted events and used for
    // presence and file and packet retrieval. Passed in the environment,
    // like the server's Elasticsearch credentials, to keep it out of the
    // generated configuration file.
    match &context.config.evebox_agent.key {
        Some(key) => {
            command.args(["--env", &format!("EVEBOX_SERVER_KEY={key}")]);
        }
        None if fpc || file_extraction => warn!(
            "File or packet retrieval is enabled but no agent key is set; the EveBox server \
             will reject the retrieval channel unless it allows unauthenticated agents"
        ),
        None => {}
    }

    command.arg(context.image_name(Container::EveBox));
    command.args(["evebox", "agent"]);
    command.args(["--config", "/config/evectl-input.yaml"]);

    command.args(["--server", &context.config.evebox_agent.server]);

    if context.config.evebox_agent.disable_certificate_validation {
        command.arg("--disable-certificate-check");
    }

    if fpc {
        command.arg(format!("--pcap-directory={PCAP_LOG_CONTAINER_DIR}"));
        command.arg(format!("--pcap-prefix={PCAP_LOG_PREFIX}"));
    }

    if file_extraction {
        command.arg(format!("--filestore-directory={FILESTORE_CONTAINER_DIR}"));
    }

    Ok(command)
}

/// Split an external input into an existing bind source and an unexpanded
/// filename pattern. The matching files do not need to exist at setup.
pub(crate) fn external_log_input(path: &Path) -> Result<(String, &str)> {
    if !path.is_absolute() {
        bail!("External EVE input must be an absolute filename or glob");
    }
    let raw = path.to_str().context("External EVE input is not UTF-8")?;
    let (parent, filename) = raw
        .rsplit_once('/')
        .context("Expected an absolute EVE input")?;
    if filename.is_empty() || matches!(filename, "." | "..") || path.is_dir() {
        bail!("Specify an EVE filename or glob, not a directory");
    }
    if parent.contains(['*', '?', '[']) || filename.contains("**") {
        bail!("Globs are only supported in the filename; recursive globs are not supported");
    }
    glob::Pattern::new(filename).context("Invalid EVE filename glob")?;
    let path = path.parent().context("Missing EVE input directory")?;
    let path = path.canonicalize().with_context(|| {
        format!(
            "Cannot access external EVE log directory {}",
            path.display()
        )
    })?;
    if !path.is_dir() {
        bail!(
            "External EVE log source is not a directory: {}",
            path.display()
        );
    }
    let source = path
        .to_str()
        .context("External EVE log directory is not UTF-8")?;
    if source.contains([',', '"', '\r', '\n']) {
        bail!(
            "External EVE log directory contains a character unsupported in container mount options"
        );
    }
    Ok((source.to_owned(), filename))
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::config::EveOutput;
    use crate::container::command_args;
    use crate::context::testing::docker_context;

    #[test]
    fn external_input_passes_a_literal_or_filename_glob_without_expanding_it() {
        let logs = tempfile::tempdir().unwrap();
        let (_root, mut context) = docker_context(Config::default());
        for filename in [
            "eve.json",
            "eve.*.json",
            "eve.[0-9]*.json",
            "a \"quoted\" # filename.json",
        ] {
            context.config.evebox_agent.external_input = Some(logs.path().join(filename));
            build_command(&context, true).unwrap();
            let yaml =
                std::fs::read(context.config_dir().join("evebox/agent/evectl-input.yaml")).unwrap();
            let config: serde_json::Value = yaml_serde::from_slice(&yaml).unwrap();
            assert_eq!(
                config["input"]["paths"],
                serde_json::json!([format!("/external-logs/{filename}")])
            );
        }
        for invalid in [
            logs.path().to_owned(),
            logs.path().join("eve.[1.json"),
            logs.path().join("*/eve.json"),
            "relative/eve.json".into(),
        ] {
            assert!(
                external_log_input(&invalid).is_err(),
                "{}",
                invalid.display()
            );
        }
    }

    #[test]
    fn external_input_is_read_only_and_managed_suricata_takes_precedence() {
        let logs = tempfile::tempdir().unwrap();
        let (_root, mut context) = docker_context(Config::default());
        context.config.evebox_agent.external_input = Some(logs.path().join("eve.*.json"));
        let args = command_args(&build_command(&context, true).unwrap());
        let source = logs.path().canonicalize().unwrap();
        assert!(args.contains(&format!(
            "--mount=type=bind,src={},dst=/external-logs,readonly",
            source.display()
        )));
        assert!(!suricata::log_dir(&context).exists());
        let config_file = context.config_dir().join("evebox/agent/evectl-input.yaml");
        let external = std::fs::read_to_string(&config_file).unwrap();
        assert!(external.contains("/external-logs/eve.*.json"));
        assert!(external.contains("delete-spool-files: false"));
        assert!(external.contains("data-directory: /var/lib/evebox"));

        // An unavailable external source must not even be validated while
        // Suricata is enabled, for either of its output formats.
        logs.close().unwrap();
        context.config.suricata.enabled = true;
        for (output, expected) in [
            (EveOutput::File, "delete-spool-files: true"),
            (EveOutput::UnixStream, "/var/run/suricata/eve.sock"),
        ] {
            context.config.suricata.eve_output = output;
            let args = command_args(&build_command(&context, false).unwrap());
            assert!(!args.iter().any(|a| a.contains("/external-logs")));
            assert!(
                std::fs::read_to_string(&config_file)
                    .unwrap()
                    .contains(expected)
            );
        }
        context.config.suricata.enabled = false;
        assert!(build_command(&context, true).is_err());
        assert!(!source.exists());
        context.config.evebox_agent.external_input = None;
        build_command(&context, true).unwrap();
        assert!(
            std::fs::read_to_string(config_file)
                .unwrap()
                .contains("delete-spool-files: true")
        );
    }

    #[test]
    fn fpc_adds_pcap_flags_and_key_to_evebox_agent() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.fpc.enabled = true;
        config.evebox_agent.enabled = true;
        config.evebox_agent.server = "https://evebox.example".to_string();
        config.evebox_agent.key = Some("secret-key".to_string());
        let (_root, context) = docker_context(config);

        let args = command_args(&build_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-directory=/var/log/suricata/pcap".to_string()));
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
        assert!(!args.iter().any(|a| a == "--agent-id"));

        // The key is a container environment variable, so it must
        // come before the image name; the pcap options are agent
        // arguments, so they must come after.
        let image = args.iter().position(|a| a == "evebox").unwrap() - 1;
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

        // The pcap options are only passed with packet capture, but the
        // key is always passed as it is the agent's identity.
        let mut context = context;
        context.config.fpc.enabled = false;
        let args = command_args(&build_command(&context, true).unwrap());
        assert!(!args.iter().any(|a| a.starts_with("--pcap-")));
        assert!(args.contains(&"EVEBOX_SERVER_KEY=secret-key".to_string()));

        // Without a key the channel is still configured; the server
        // decides whether to accept it.
        context.config.fpc.enabled = true;
        context.config.evebox_agent.key = None;
        let args = command_args(&build_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("EVEBOX_SERVER_KEY=")));
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
                            config.evebox_agent.key = Some("secret-key".to_string());
                            let (_root, mut context) = docker_context(config);

                            let args = command_args(&build_command(&context, detached).unwrap());
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
                            assert!(key.is_some());
                            if let Some(position) = key {
                                assert_eq!(args[position - 1], "--env");
                                assert!(position < agent - 2);
                            }
                            assert!(!args.iter().any(|a| a == "--agent-id"));

                            context.config.evebox_agent.key = None;
                            let args = command_args(&build_command(&context, detached).unwrap());
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
}
