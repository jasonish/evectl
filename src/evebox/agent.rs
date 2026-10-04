// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

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

    let libdir = context.data_dir().join("evebox").join("agent");
    let logdir = suricata::log_dir(context);
    std::fs::create_dir_all(&libdir)?;
    std::fs::create_dir_all(&logdir)?;

    let mut volumes = vec![
        context.manager.bind_mount(&logdir, "/var/log/suricata"),
        context.manager.bind_mount(&libdir, "/var/lib/evebox"),
    ];

    let configdir = context.config_dir().join("evebox").join("agent");
    if use_socket {
        let rundir = suricata::run_dir(context);
        std::fs::create_dir_all(&rundir)?;
        volumes.push(context.manager.bind_mount(&rundir, "/var/run/suricata"));

        configs::write_evebox_agent_socket_config(&configdir.join("evectl-input.yaml"))?;
    } else {
        configs::write_evebox_agent_file_config(&configdir.join("evectl-input.yaml"))?;
    }
    volumes.push(context.manager.bind_mount(&configdir, "/config"));

    for volume in volumes {
        command.arg(format!("--volume={}", volume));
    }

    // For now use host networking. We don't listen on any ports but
    // may need to connect to localhost of the host system.
    command.arg("--net=host");

    let fpc = context.config.uses_fpc();
    let file_extraction = context.config.uses_file_extraction();
    if fpc || file_extraction {
        // The agent key authenticates the file and packet retrieval channel to
        // the server. Passed in the environment, like the server's
        // Elasticsearch credentials, to keep it out of the generated
        // configuration file.
        match &context.config.evebox_agent.key {
            Some(key) => {
                command.args(["--env", &format!("EVEBOX_SERVER_KEY={key}")]);
            }
            None => warn!(
                "File or packet retrieval is enabled but no agent key is set; the EveBox server \
                 will reject the retrieval channel unless it allows unauthenticated agents"
            ),
        }
    }

    command.arg(context.image_name(Container::EveBox));
    command.args(["evebox", "agent"]);
    command.args(["--config", "/config/evectl-input.yaml"]);

    command.args(["--server", &context.config.evebox_agent.server]);

    if context.config.evebox_agent.disable_certificate_validation {
        command.arg("--disable-certificate-check");
    }

    // Stamped on every event and claimed on the retrieval
    // channel, so the server routes file and packet requests for this
    // sensor's events back to this agent.
    if let Some(agent_id) = &context.config.evebox_agent.agent_id {
        command.args(["--agent-id", agent_id]);
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

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::config::EveOutput;
    use crate::container::command_args;
    use crate::context::testing::docker_context;

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

        let args = command_args(&build_command(&context, true).unwrap());
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
        let args = command_args(&build_command(&context, true).unwrap());
        assert!(args.contains(&"--agent-id".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("--pcap-")));
        assert!(!args.iter().any(|a| a.starts_with("EVEBOX_SERVER_KEY=")));

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
                            config.evebox_agent.agent_id = Some("sensor-1".to_string());
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
                            assert_eq!(key.is_some(), suricata && (fpc || extraction));
                            if let Some(position) = key {
                                assert_eq!(args[position - 1], "--env");
                                assert!(position < agent - 2);
                            }
                            let id = args.iter().position(|a| a == "--agent-id").unwrap();
                            assert_eq!(args[id + 1], "sensor-1");

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
