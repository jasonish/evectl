// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

#[cfg(not(windows))]
pub(crate) mod agent;
pub(crate) mod configuration;
#[cfg(not(windows))]
pub(crate) mod server;

use std::process::Command;

use crate::container::{Container, ProbeTarget};
use crate::prelude::*;

/// Query the version of EveBox in the named running container.
pub(crate) fn running_version(context: &Context, container_name: &str) -> Result<Option<String>> {
    version_probe(context, ProbeTarget::Container(container_name))
}

/// Query the version of EveBox in the configured image by running a
/// throwaway container. Returns None if the image is not present, as
/// running it would trigger a pull.
pub(crate) fn image_version(context: &Context) -> Result<Option<String>> {
    version_probe(
        context,
        ProbeTarget::Image(&context.image_name(Container::EveBox)),
    )
}

fn version_probe(context: &Context, target: ProbeTarget<'_>) -> Result<Option<String>> {
    match context
        .manager
        .probe_command(target, &["evebox", "version"])
    {
        Some(command) => run_version_command(command),
        None => Ok(None),
    }
}

/// Run a command that prints the EveBox version, for example `evebox
/// version`, and parse the version from its output.
pub(crate) fn run_version_command(command: Command) -> Result<Option<String>> {
    let (stdout, _) = crate::container::version_output(command, "EveBox")?;
    Ok(parse_version(&stdout))
}

/// Parse the output of `evebox version`, for example
/// `EveBox Version 0.28.0 (rev abcdef0); x86_64-unknown-linux-musl`.
/// Development versions include the revision as they share a version
/// number across builds.
pub(crate) fn parse_version(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?i)\bEveBox Version\s+(\S+)(?:\s+\(rev\s+([0-9a-f]+)\))?")
        .expect("valid EveBox version regex");
    let captures = re.captures(text)?;
    let version = captures.get(1)?.as_str().to_string();
    match captures.get(2) {
        Some(rev) if version.contains('-') => Some(format!("{version} rev {}", rev.as_str())),
        _ => Some(version),
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::config::EveOutput;
    use crate::container::command_args;
    use crate::context::testing::docker_context;

    #[test]
    fn parses_evebox_versions() {
        assert_eq!(
            parse_version("EveBox Version 0.28.0 (rev 4884466d); x86_64-unknown-linux-musl"),
            Some("0.28.0".to_string())
        );
        assert_eq!(
            parse_version("EveBox Version 0.29.0-dev (rev 4884466d); x86_64-unknown-linux-musl"),
            Some("0.29.0-dev rev 4884466d".to_string())
        );
        assert_eq!(
            parse_version("EveBox Version 0.28.0"),
            Some("0.28.0".to_string())
        );
        assert_eq!(parse_version("unrecognized output"), None);
    }

    #[test]
    fn fpc_with_both_server_and_agent_serves_each_spool() {
        let mut config = Config::default();
        config.suricata.enabled = true;
        config.suricata.eve_output = EveOutput::File;
        config.fpc.enabled = true;
        config.evebox_server.enabled = true;
        config.evebox_agent.enabled = true;
        let (_root, context) = docker_context(config);

        let args = command_args(&agent::build_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
        let args = command_args(&server::build_command(&context, true).unwrap());
        assert!(args.contains(&"--pcap-prefix=log.".to_string()));
    }

    #[test]
    fn evebox_commands_switch_between_socket_and_file_inputs() {
        let mut socket_config = Config::default();
        socket_config.suricata.enabled = true;
        socket_config.evebox_server.enabled = true;
        let (_socket_root, socket_context) = docker_context(socket_config);

        let server = server::build_command(&socket_context, true).unwrap();
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

        let agent = agent::build_command(&agent_context, true).unwrap();
        let agent_args = command_args(&agent);
        assert!(agent_args.contains(&"--user=0:998".to_string()));
        assert!(agent_args.contains(&"/config/evectl-input.yaml".to_string()));
        assert!(!agent_args.contains(&"/var/log/suricata/eve.json".to_string()));

        let mut file_config = Config::default();
        file_config.suricata.enabled = true;
        file_config.suricata.eve_output = EveOutput::File;
        file_config.evebox_server.enabled = true;
        let (_file_root, file_context) = docker_context(file_config);

        let file_server = server::build_command(&file_context, true).unwrap();
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

        let file_agent = agent::build_command(&file_agent_context, true).unwrap();
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
}
