// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use std::process::Command;

use crate::configs;
use crate::container::{Container, RESTART_POLICY_ARG, RunCommandBuilder};
use crate::prelude::*;
use crate::suricata::{self, FILESTORE_CONTAINER_DIR, PCAP_LOG_CONTAINER_DIR, PCAP_LOG_PREFIX};

pub(crate) fn container_name(context: &Context) -> String {
    format!("{}-evebox-server", context.container_prefix())
}

/// Host path of the EveBox server configuration directory, bind
/// mounted into the container as /config.
fn config_dir(context: &Context) -> std::path::PathBuf {
    context.config_dir().join("evebox").join("server")
}

pub(crate) fn start(context: &Context) -> Result<()> {
    crate::container::start_detached(context, &container_name(context), "EveBox-Server", || {
        build_command(context, true)
    })
}

pub(crate) fn build_command(context: &Context, daemon: bool) -> Result<Command> {
    let config = &context.config.evebox_server;
    let use_socket = context.config.uses_eve_socket();
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--name");
    command.arg(container_name(context));

    if use_socket {
        command.arg("--user=0:998");
    }

    let publish_arg = if context.config.evebox_server.allow_remote {
        if let Some(bind_value) = &config.bind_address {
            let ip = crate::system::resolve_interface_or_ip(bind_value)?;
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

    let host_log_directory = suricata::log_dir(context);
    std::fs::create_dir_all(&host_log_directory)?;
    command.arg(format!(
        "--volume={}",
        context
            .manager
            .bind_mount(&host_log_directory, "/var/log/suricata")
    ));

    if use_socket {
        let host_run_directory = suricata::run_dir(context);
        std::fs::create_dir_all(&host_run_directory)?;
        command.arg(format!(
            "--volume={}",
            context
                .manager
                .bind_mount(&host_run_directory, "/var/run/suricata")
        ));
    }

    let host_config_directory = config_dir(context);
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

    if context.config.uses_fpc() {
        command.arg(format!("--pcap-directory={PCAP_LOG_CONTAINER_DIR}"));
        command.arg(format!("--pcap-prefix={PCAP_LOG_PREFIX}"));
    }

    if context.config.uses_file_extraction() {
        command.arg(format!("--filestore-directory={FILESTORE_CONTAINER_DIR}"));
    }

    Ok(command)
}

/// Interactively reset the "admin" user's password by removing and
/// re-adding the user with the EveBox image.
pub(crate) fn reset_password(context: &Context) -> Result<()> {
    let host_config_directory = config_dir(context);
    std::fs::create_dir_all(&host_config_directory)?;
    let volume = context
        .manager
        .bind_mount(&host_config_directory, "/config");

    let users_command = |args: &[&str]| {
        RunCommandBuilder::new(context.manager, context.image_name(Container::EveBox))
            .rm()
            .it()
            .volumes(&[&volume])
            .args(&["evebox", "-D", "/config", "config", "users"])
            .args(args)
            .build()
    };

    let mut command = users_command(&["rm", "admin"]);
    info!("Executing {:?}", command);
    let _ = command.status();

    let _ = users_command(&["add", "--username", "admin"]).status();
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::config::EveOutput;
    use crate::container::command_args;
    use crate::context::testing::docker_context;

    #[test]
    fn fpc_adds_pcap_flags_to_evebox_server() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.fpc.enabled = true;
        config.evebox_server.enabled = true;
        let (_root, context) = docker_context(config);

        let args = command_args(&build_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-directory=/var/log/suricata/pcap".to_string()));
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));

        let mut context = context;
        context.config.fpc.enabled = false;
        let args = command_args(&build_command(&context, true).unwrap());
        assert!(!args.iter().any(|a| a.starts_with("--pcap-")));
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

                let args = command_args(&build_command(&context, detached).unwrap());
                let filestore = args
                    .iter()
                    .position(|a| a == "--filestore-directory=/var/log/suricata/filestore")
                    .unwrap();
                assert!(filestore > args.iter().position(|a| a == "server").unwrap());
                assert!(!args.iter().any(|a| a.starts_with("--pcap-")));

                for (suricata, extraction) in [(false, true), (true, false)] {
                    context.config.suricata.enabled = suricata;
                    context.config.suricata.file_extraction.enabled = extraction;
                    let args = command_args(&build_command(&context, detached).unwrap());
                    assert!(!args.iter().any(|a| a.starts_with("--filestore-")));
                }
            }
        }
    }

    #[test]
    fn reset_password_commands_mount_the_server_config() {
        let (_root, context) = docker_context(Config::default());
        let volume = context.manager.bind_mount(&config_dir(&context), "/config");
        let args = command_args(
            &RunCommandBuilder::new(context.manager, context.image_name(Container::EveBox))
                .rm()
                .it()
                .volumes(&[&volume])
                .args(&["evebox", "-D", "/config", "config", "users", "rm", "admin"])
                .build(),
        );
        assert_eq!(args[0], "run");
        assert!(args.contains(&"--rm".to_string()));
        assert!(args.contains(&"-it".to_string()));
        assert_eq!(
            args.iter().filter(|a| a.starts_with("--volume=")).count(),
            1
        );
        assert!(args.ends_with(&[
            "evebox".to_string(),
            "-D".to_string(),
            "/config".to_string(),
            "config".to_string(),
            "users".to_string(),
            "rm".to_string(),
            "admin".to_string()
        ]));
    }
}
