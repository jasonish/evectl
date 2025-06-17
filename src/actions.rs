// SPDX-FileCopyrightText: (C) 2021 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

use crate::prelude::*;

use std::collections::HashSet;

use crate::container::{CommandExt, SuricataContainer};
use crate::context::Context;
use crate::ruleindex::RuleIndex;
use crate::service::{ServiceControl, ServiceDefinition};

pub(crate) fn force_suricata_logrotate(context: &Context) {
    let _ = context
        .manager
        .command()
        .args([
            "exec",
            &crate::suricata::container_name(context),
            "logrotate",
            "-fv",
            "/etc/logrotate.d/suricata",
        ])
        .status();
}

pub(crate) fn load_rule_index(context: &Context) -> Result<RuleIndex> {
    let container = SuricataContainer::new(context.clone());
    let output = container
        .run()
        .rm()
        .args(&["cat", "/var/lib/suricata/update/cache/index.yaml"])
        .build()
        .status_output()?;
    let index: RuleIndex = serde_yaml::from_slice(&output)?;
    Ok(index)
}

pub(crate) fn get_enabled_ruleset(context: &Context) -> Result<HashSet<String>> {
    let mut enabled: HashSet<String> = HashSet::new();
    let container = SuricataContainer::new(context.clone());
    let output = container
        .run()
        .args(&["suricata-update", "list-sources", "--enabled"])
        .build()
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = regex::Regex::new(r"^[\s]*\-\s*(.*)").unwrap();
    for line in stdout.lines() {
        if let Some(caps) = re.captures(line) {
            enabled.insert(String::from(&caps[1]));
        }
    }
    Ok(enabled)
}

pub(crate) fn enable_ruleset(context: &Context, ruleset: &str) -> Result<()> {
    let container = SuricataContainer::new(context.clone());
    container
        .run()
        .args(&["suricata-update", "enable-source", ruleset])
        .build()
        .status_ok()?;
    Ok(())
}

pub(crate) fn disable_ruleset(context: &Context, ruleset: &str) -> Result<()> {
    let container = SuricataContainer::new(context.clone());
    container
        .run()
        .args(&["suricata-update", "disable-source", ruleset])
        .build()
        .status_ok()?;
    Ok(())
}

pub(crate) fn update_rules(context: &Context) -> Result<()> {
    if !context.config.suricata.enabled {
        bail!("Suricata is not enabled.");
    }
    let container = SuricataContainer::new(context.clone());

    let mut volumes = vec![];

    let config_filenames = ["enable.conf", "disable.conf", "modify.conf"];
    for filename in config_filenames {
        let source = context.config_dir().join(filename);
        let target = format!("/etc/suricata/{}", filename);
        if source.exists() {
            info!("Bind-mounting {} to {}", source.display(), &target);
            volumes.push(format!("{}:{}", source.display(), target));
        }
    }

    info!("Updating Suricata rule sources...");
    if let Err(err) = container
        .run()
        .rm()
        .it()
        .args(&["suricata-update", "update-sources"])
        .build()
        .status_ok()
    {
        error!("Rule source update did not complete successfully: {err}");
    }

    info!("Updating Suricata rules...");
    if let Err(err) = container
        .run()
        .rm()
        .it()
        .volumes(&volumes)
        .args(&["suricata-update"])
        .build()
        .status_ok()
    {
        error!("Rule update did not complete successfully: {err}");
    }
    Ok(())
}

fn create_evebox_server_service_definition(context: &Context) -> Result<ServiceDefinition> {
    let config = &context.config.evebox_server;
    let mut env_vars = std::collections::HashMap::new();
    let mut args = vec!["evebox".to_string(), "server".to_string()];

    // Add configuration arguments
    if context.config.evebox_server.no_tls {
        args.push("--no-tls".to_string());
    }
    if context.config.evebox_server.no_auth {
        args.push("--no-auth".to_string());
    }
    args.push("--host=[::0]".to_string());

    // Configure Elasticsearch or SQLite
    if config.use_external_elasticsearch {
        args.push("--elasticsearch".to_string());
        args.push(config.elasticsearch_client.url.clone().ok_or_else(|| {
            anyhow::anyhow!("External Elasticsearch URL not set in configuration")
        })?);
        if config.elasticsearch_client.disable_certificate_validation {
            args.push("--no-check-certificate".to_string());
        }

        // Environment variables for Elasticsearch
        if let Some(username) = &config.elasticsearch_client.username {
            env_vars.insert(
                "EVEBOX_ELASTICSEARCH_USERNAME".to_string(),
                username.clone(),
            );
        }
        if let Some(password) = &config.elasticsearch_client.password {
            env_vars.insert(
                "EVEBOX_ELASTICSEARCH_PASSWORD".to_string(),
                password.clone(),
            );
        }
        env_vars.insert(
            "EVEBOX_ELASTICSEARCH_INDEX".to_string(),
            config
                .elasticsearch_client
                .index
                .as_deref()
                .unwrap_or("evebox")
                .to_string(),
        );
    } else if context.config.elasticsearch.enabled {
        args.push("--elasticsearch".to_string());
        args.push("http://localhost:9200".to_string()); // Assuming localhost for Windows
        env_vars.insert(
            "EVEBOX_ELASTICSEARCH_INDEX".to_string(),
            "evebox".to_string(),
        );
    } else {
        args.push("--sqlite".to_string());
    }

    // Set up directories
    let host_config_directory = context.config_dir().join("evebox").join("server");
    let host_data_directory = context.data_dir().join("evebox").join("server");
    let host_log_directory = context.data_dir().join("suricata").join("log");
    std::fs::create_dir_all(&host_config_directory)?;
    std::fs::create_dir_all(&host_data_directory)?;

    // Use container paths for Linux, host paths for Windows
    if cfg!(windows) {
        args.push("--data-directory".to_string());
        args.push(host_data_directory.to_string_lossy().to_string());
        args.push("--config-directory".to_string());
        args.push(host_config_directory.to_string_lossy().to_string());

        // Add eve.json path
        let eve_json_path = host_log_directory.join("eve.json");
        args.push(eve_json_path.to_string_lossy().to_string());
    } else {
        // For containers, use the container paths
        args.push("--data-directory".to_string());
        args.push("/data".to_string());
        args.push("--config-directory".to_string());
        args.push("/config".to_string());

        // Add eve.json path
        args.push("/var/log/suricata/eve.json".to_string());

        // Store volume mappings in env_vars for the container manager
        env_vars.insert(
            "VOLUME_CONFIG".to_string(),
            format!("{}:/config", host_config_directory.display()),
        );
        env_vars.insert(
            "VOLUME_DATA".to_string(),
            format!("{}:/data", host_data_directory.display()),
        );
        env_vars.insert(
            "VOLUME_LOG".to_string(),
            format!("{}:/var/log/suricata", host_log_directory.display()),
        );

        // Port publishing for containers
        if context.config.evebox_server.allow_remote {
            env_vars.insert("PUBLISH_PORT".to_string(), "5636:5636".to_string());
        } else {
            env_vars.insert(
                "PUBLISH_PORT".to_string(),
                "127.0.0.1:5636:5636".to_string(),
            );
        }
    }

    // On Windows, we need to find the EveBox executable
    let executable_path = if cfg!(windows) {
        // Try to find evebox.exe in the installation directory (same as where we install it)
        if let Some(data_local_dir) = dirs::data_local_dir() {
            let evebox_exe = data_local_dir
                .join("evectl")
                .join("evebox")
                .join("evebox.exe");
            info!("Looking for EveBox at: {:?}", evebox_exe);
            if evebox_exe.exists() {
                // Canonicalize the path to ensure it's absolute and properly formatted
                match evebox_exe.canonicalize() {
                    Ok(canonical_path) => {
                        info!("Found EveBox at: {:?}", canonical_path);
                        canonical_path
                    }
                    Err(e) => {
                        warn!("Failed to canonicalize EveBox path: {}", e);
                        evebox_exe
                    }
                }
            } else {
                warn!("EveBox not found at expected location: {:?}", evebox_exe);
                // Check a few alternative locations before falling back
                let alt_locations = vec![
                    std::path::PathBuf::from(
                        r"C:\Users\jason\AppData\Local\evectl\evebox\evebox.exe",
                    ),
                    context.data_dir().join("evebox").join("evebox.exe"),
                ];

                let mut found_path = None;
                for alt_path in alt_locations {
                    info!("Checking alternative location: {:?}", alt_path);
                    if alt_path.exists() {
                        info!("Found EveBox at alternative location: {:?}", alt_path);
                        found_path = Some(alt_path);
                        break;
                    }
                }

                // Use found path or fallback to system PATH
                found_path.unwrap_or_else(|| {
                    warn!("EveBox not found at any expected location, falling back to PATH");
                    std::path::PathBuf::from("evebox.exe")
                })
            }
        } else {
            warn!("Could not determine local data directory, falling back to PATH");
            // Fallback to system PATH if we can't find local data dir
            std::path::PathBuf::from("evebox.exe")
        }
    } else {
        // On Linux, use the container image
        std::path::PathBuf::from(&context.evebox_image)
    };

    Ok(ServiceDefinition {
        name: crate::evebox::server::container_name(context),
        executable_path,
        args,
        working_dir: Some(context.root.clone()),
        env_vars,
        log_file: Some(
            context
                .data_dir()
                .join("evebox")
                .join("server")
                .join("evebox-server.log"),
        ),
    })
}

pub(crate) fn start_evebox_server(context: &Context) -> Result<()> {
    let service_def = create_evebox_server_service_definition(context)?;
    context.service_manager.start(&service_def)
}

fn create_evebox_agent_service_definition(context: &Context) -> Result<ServiceDefinition> {
    let mut env_vars = std::collections::HashMap::new();
    let mut args = vec!["evebox".to_string(), "agent".to_string()];

    args.push("--server".to_string());
    args.push(context.config.evebox_agent.server.clone());

    if context.config.evebox_agent.disable_certificate_validation {
        args.push("--disable-certificate-check".to_string());
    }

    // Create agent data directory
    let libdir = context.data_dir().join("evebox").join("agent");
    let logdir = context.data_dir().join("suricata").join("log");
    std::fs::create_dir_all(&libdir)?;

    // Add eve.json path
    if cfg!(windows) {
        let eve_json_path = logdir.join("eve.json");
        args.push(eve_json_path.to_string_lossy().to_string());
    } else {
        // For containers, use the container path
        args.push("/var/log/suricata/eve.json".to_string());

        // Store volume mappings in env_vars for the container manager
        env_vars.insert(
            "VOLUME_LOG".to_string(),
            format!("{}:/var/log/suricata", logdir.display()),
        );
        env_vars.insert(
            "VOLUME_LIB".to_string(),
            format!("{}:/var/lib/evebox", libdir.display()),
        );

        // Use host networking for the agent
        env_vars.insert("NET_MODE".to_string(), "host".to_string());
    }

    // On Windows, we need to find the EveBox executable
    let executable_path = if cfg!(windows) {
        // Try to find evebox.exe in the installation directory (same as where we install it)
        if let Some(data_local_dir) = dirs::data_local_dir() {
            let evebox_exe = data_local_dir
                .join("evectl")
                .join("evebox")
                .join("evebox.exe");
            info!("Looking for EveBox at: {:?}", evebox_exe);
            if evebox_exe.exists() {
                // Canonicalize the path to ensure it's absolute and properly formatted
                match evebox_exe.canonicalize() {
                    Ok(canonical_path) => {
                        info!("Found EveBox at: {:?}", canonical_path);
                        canonical_path
                    }
                    Err(e) => {
                        warn!("Failed to canonicalize EveBox path: {}", e);
                        evebox_exe
                    }
                }
            } else {
                warn!("EveBox not found at expected location: {:?}", evebox_exe);
                // Check a few alternative locations before falling back
                let alt_locations = vec![
                    std::path::PathBuf::from(
                        r"C:\Users\jason\AppData\Local\evectl\evebox\evebox.exe",
                    ),
                    context.data_dir().join("evebox").join("evebox.exe"),
                ];

                let mut found_path = None;
                for alt_path in alt_locations {
                    info!("Checking alternative location: {:?}", alt_path);
                    if alt_path.exists() {
                        info!("Found EveBox at alternative location: {:?}", alt_path);
                        found_path = Some(alt_path);
                        break;
                    }
                }

                // Use found path or fallback to system PATH
                found_path.unwrap_or_else(|| {
                    warn!("EveBox not found at any expected location, falling back to PATH");
                    std::path::PathBuf::from("evebox.exe")
                })
            }
        } else {
            warn!("Could not determine local data directory, falling back to PATH");
            // Fallback to system PATH if we can't find local data dir
            std::path::PathBuf::from("evebox.exe")
        }
    } else {
        // On Linux, use the container image
        std::path::PathBuf::from(&context.evebox_image)
    };

    Ok(ServiceDefinition {
        name: crate::evebox::agent::container_name(context),
        executable_path,
        args,
        working_dir: Some(context.root.clone()),
        env_vars: std::collections::HashMap::new(),
        log_file: Some(
            context
                .data_dir()
                .join("evebox")
                .join("agent")
                .join("evebox-agent.log"),
        ),
    })
}

pub(crate) fn start_evebox_agent(context: &Context) -> Result<()> {
    let service_def = create_evebox_agent_service_definition(context)?;
    context.service_manager.start(&service_def)
}

pub(crate) fn stop_evebox_server(context: &Context) -> Result<()> {
    context
        .service_manager
        .stop(&crate::evebox::server::container_name(context))
}

pub(crate) fn _stop_evebox_agent(context: &Context) -> Result<()> {
    context
        .service_manager
        .stop(&crate::evebox::agent::container_name(context))
}

pub(crate) fn is_evebox_server_running(context: &Context) -> bool {
    context
        .service_manager
        .is_running(&crate::evebox::server::container_name(context))
}

pub(crate) fn is_evebox_agent_running(context: &Context) -> bool {
    context
        .service_manager
        .is_running(&crate::evebox::agent::container_name(context))
}

fn create_suricata_service_definition(context: &Context) -> Result<ServiceDefinition> {
    let mut env_vars = std::collections::HashMap::new();
    let mut args = vec![];

    // Create required directories
    crate::suricata::mkdirs(context)?;

    // Configuration file
    args.push("-c".to_string());
    if cfg!(windows) {
        // Use relative path since we're setting working directory to Suricata install dir
        args.push(".\\suricata.yaml".to_string());
    } else {
        let config_file = context.config_dir().join("suricata.yaml");
        if !config_file.exists() {
            bail!(
                "Suricata configuration file not found: {}",
                config_file.display()
            );
        }
        args.push("/config/suricata.yaml".to_string());
    }

    // Add interfaces
    for interface in &context.config.suricata.interfaces {
        args.push("-i".to_string());

        // On Windows, ensure the interface name is properly formatted
        let interface_name = if cfg!(windows) {
            // Interface should be in the format \Device\NPF_{GUID}
            if interface.starts_with("\\Device\\NPF_{") && interface.ends_with("}") {
                // Already in correct format
                interface.clone()
            } else if interface.starts_with("\\Device\\NPF_") {
                // Has the prefix but might be missing braces around GUID
                let guid_part = interface.trim_start_matches("\\Device\\NPF_");
                if guid_part.starts_with('{') && guid_part.ends_with('}') {
                    // GUID already has braces
                    interface.clone()
                } else {
                    // Add braces around the GUID
                    format!("\\Device\\NPF_{{{}}}", guid_part)
                }
            } else if interface.starts_with("{") && interface.ends_with("}") {
                // If it's just a GUID with braces, format it properly
                format!("\\Device\\NPF_{}", interface)
            } else if interface.len() == 36
                && interface.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            {
                // Looks like a bare GUID without braces (36 chars: 8-4-4-4-12)
                format!("\\Device\\NPF_{{{}}}", interface)
            } else {
                warn!("Interface name '{}' may not be in correct format for Windows, expected format: \\Device\\NPF_{{GUID}}", interface);
                interface.clone()
            }
        } else {
            interface.clone()
        };

        args.push(interface_name);
    }

    // On Windows, add log directory argument and verbose logging
    if cfg!(windows) {
        let log_dir = context.data_dir().join("suricata").join("log");
        args.push("-l".to_string());
        args.push(log_dir.to_string_lossy().to_string());

        // Add verbose logging for debugging (use -v instead of -vvv)
        args.push("-v".to_string());

        // Add rules file argument
        let rules_file = context
            .config_dir()
            .join("suricata")
            .join("lib")
            .join("rules")
            .join("suricata.rules");
        if rules_file.exists() {
            args.push("-S".to_string());
            args.push(rules_file.to_string_lossy().to_string());
        }
    }

    // Set sensor name if configured
    if let Some(sensor_name) = &context.config.suricata.sensor_name {
        args.push("--set".to_string());
        args.push(format!("sensor-name={}", sensor_name));
    }

    // Add BPF filter if configured
    if let Some(bpf) = &context.config.suricata.bpf {
        args.push(bpf.clone());
    }

    // Set up directories
    let host_config_dir = context.config_dir().join("suricata");
    let host_lib_dir = host_config_dir.join("lib");
    let host_log_dir = context.data_dir().join("suricata").join("log");
    let host_run_dir = context.data_dir().join("suricata").join("run");

    if !cfg!(windows) {
        // For containers, set up volume mappings
        env_vars.insert(
            "VOLUME_CONFIG".to_string(),
            format!("{}:/config", host_config_dir.display()),
        );
        env_vars.insert(
            "VOLUME_LIB".to_string(),
            format!("{}:/var/lib/suricata", host_lib_dir.display()),
        );
        env_vars.insert(
            "VOLUME_LOG".to_string(),
            format!("{}:/var/log/suricata", host_log_dir.display()),
        );
        env_vars.insert(
            "VOLUME_RUN".to_string(),
            format!("{}:/var/run/suricata", host_run_dir.display()),
        );

        // Network mode
        env_vars.insert("NET_MODE".to_string(), "host".to_string());
    }

    // Determine executable path
    let executable_path = if cfg!(windows) {
        // On Windows, try to find Suricata executable
        let common_paths = [
            r"C:\Program Files\Suricata\suricata.exe",
            r"C:\Program Files (x86)\Suricata\suricata.exe",
        ];

        let mut found_path = None;
        for path in &common_paths {
            if std::path::Path::new(path).exists() {
                found_path = Some(std::path::PathBuf::from(path));
                break;
            }
        }

        // Check if suricata is in PATH
        if found_path.is_none() {
            if let Ok(output) = std::process::Command::new("where")
                .arg("suricata.exe")
                .output()
            {
                if output.status.success() {
                    if let Ok(path) = String::from_utf8(output.stdout) {
                        if let Some(line) = path.lines().next() {
                            found_path = Some(std::path::PathBuf::from(line.trim()));
                        }
                    }
                }
            }
        }

        found_path.unwrap_or_else(|| std::path::PathBuf::from("suricata.exe"))
    } else {
        // On Linux, use the container image
        std::path::PathBuf::from(&context.suricata_image)
    };

    // Log the service definition for debugging
    info!("Creating Suricata service definition:");
    info!("  Executable: {:?}", executable_path);
    info!("  Arguments: {:?}", args);
    info!("  Working directory: {:?}", context.root);
    if !env_vars.is_empty() {
        info!("  Environment variables: {:?}", env_vars);
    }
    if cfg!(windows) {
        info!("  Log file: {:?}", host_log_dir.join("suricata.log"));
    }

    Ok(ServiceDefinition {
        name: crate::suricata::container_name(context),
        executable_path,
        args,
        working_dir: if cfg!(windows) {
            // On Windows, set working directory to Suricata installation directory
            // This ensures relative paths like ".\suricata.yaml" work correctly
            Some(std::path::PathBuf::from(r"C:\Program Files\Suricata"))
        } else {
            Some(context.root.clone())
        },
        env_vars,
        log_file: if cfg!(windows) {
            Some(host_log_dir.join("suricata.log"))
        } else {
            None
        },
    })
}

pub(crate) fn start_suricata(context: &Context) -> Result<()> {
    let service_def = create_suricata_service_definition(context)?;
    context.service_manager.start(&service_def)
}

pub(crate) fn stop_suricata(context: &Context) -> Result<()> {
    context
        .service_manager
        .stop(&crate::suricata::container_name(context))
}

pub(crate) fn is_suricata_running(context: &Context) -> bool {
    context
        .service_manager
        .is_running(&crate::suricata::container_name(context))
}
