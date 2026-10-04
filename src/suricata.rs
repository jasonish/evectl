// SPDX-FileCopyrightText: (C) 2025 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

pub(crate) mod configuration;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use semver::Version;

use crate::config::{EveOutput, FileExtractionConfig, FpcConfig};
use crate::container::{CommandExt, Container, ProbeTarget, RESTART_POLICY_ARG, SuricataContainer};
use crate::prelude::*;

/// Path of the EVE Unix socket inside the containers, shared with the
/// EveBox server and agent through the Suricata run volume.
pub(crate) const EVE_SOCKET_CONTAINER_PATH: &str = "/var/run/suricata/eve.sock";

/// Suricata pcap-log spool directory inside the containers. Shared
/// with the EveBox server and agent through the Suricata log volume.
pub(crate) const PCAP_LOG_CONTAINER_DIR: &str = "/var/log/suricata/pcap";
pub(crate) const PCAP_LOG_PREFIX: &str = "log.";

/// Suricata file-store (extracted files) directory inside the
/// container, on the Suricata log volume.
pub(crate) const FILESTORE_CONTAINER_DIR: &str = "/var/log/suricata/filestore";

pub(crate) const MINIMUM_SURICATA_VERSION: &str = "8.0.6";

pub(crate) fn container_name(context: &Context) -> String {
    format!("{}-suricata", context.container_prefix())
}

/// Host path of the Suricata library directory (rules, update cache),
/// bind mounted into the containers as /var/lib/suricata.
pub(crate) fn lib_dir(context: &Context) -> PathBuf {
    context.config_dir().join("suricata").join("lib")
}

/// Host path of the Suricata log directory, bind mounted into the
/// containers as /var/log/suricata.
pub(crate) fn log_dir(context: &Context) -> PathBuf {
    context.data_dir().join("suricata").join("log")
}

/// Host path of the Suricata run directory (EVE socket), bind mounted
/// into the containers as /var/run/suricata.
pub(crate) fn run_dir(context: &Context) -> PathBuf {
    context.data_dir().join("suricata").join("run")
}

/// Host path of the packet capture spool, bind mounted into the
/// containers as /var/log/suricata/pcap.
pub(crate) fn pcap_dir(context: &Context) -> PathBuf {
    log_dir(context).join("pcap")
}

/// Host path of the extracted files (file-store) directory, bind
/// mounted into the Suricata container as /var/log/suricata/filestore.
/// Created by Suricata when file extraction is enabled.
pub(crate) fn filestore_dir(context: &Context) -> PathBuf {
    log_dir(context).join("filestore")
}

pub(crate) fn mkdirs(context: &Context) -> Result<()> {
    let lib_dir = lib_dir(context);
    let dirs = vec![
        lib_dir.clone(),
        lib_dir.join("rules"),
        lib_dir.join("update"),
        lib_dir.join("update").join("cache"),
        log_dir(context),
        pcap_dir(context),
        run_dir(context),
    ];

    for dir in dirs {
        info!("Creating directory: {}", dir.display());
        std::fs::create_dir_all(&dir)?;
    }

    Ok(())
}

/// Remove the Suricata engine log (suricata.log). Done on each start
/// of Suricata to keep it from growing unbounded, as log rotation is
/// no longer used.
pub(crate) fn remove_engine_log(context: &Context) {
    let path = log_dir(context).join("suricata.log");
    if !path.exists() {
        return;
    }

    // The log is created by Suricata in the container and may not be
    // removable by the host user. Use a short-lived Suricata container so
    // the bind-mounted file is removed with the same container privileges.
    let container = SuricataContainer::new(context.clone());
    if let Err(err) = container
        .run()
        .rm()
        .args(&["rm", "-f", "/var/log/suricata/suricata.log"])
        .build()
        .status_ok()
    {
        warn!("Failed to remove {}: {}", path.display(), err);
    }
}

/// Return the time of the last rule update, formatted for display, or
/// None if the rules have never been updated. The time is taken from
/// the rules file written by suricata-update.
pub(crate) fn last_rule_update(context: &Context) -> Option<String> {
    let path = lib_dir(context).join("rules").join("suricata.rules");
    let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
    Some(crate::status::format_time_with_age(
        modified,
        std::time::SystemTime::now(),
    ))
}

pub(crate) fn build_command(context: &Context, detached: bool) -> Result<Command> {
    warn_if_unsupported_version(context);
    let config = dump_config(context)?;
    let set_args = set_args(
        &config,
        context.config.suricata.eve_output,
        &context.config.effective_fpc_config(),
        &context.config.suricata.file_extraction,
    )?;

    let interface = match context.config.suricata.interfaces.first() {
        Some(interface) => interface,
        None => bail!("no network interface set"),
    };

    let mut command = context.manager.command();
    command.args([
        "run",
        "--name",
        &container_name(context),
        "--net=host",
        "--cap-add=sys_nice",
        "--cap-add=net_admin",
        "--cap-add=net_raw",
    ]);

    if detached {
        command.args(["--detach", RESTART_POLICY_ARG]);
    }

    let path = context.config_dir().join("evectl-suricata.yaml");
    if let Err(err) = crate::configs::write_suricata_stub(&path) {
        error!("Failed to write Suricata include: {err}");
    } else {
        command.arg(format!(
            "--volume={}",
            context
                .manager
                .bind_mount(&path, "/config/evectl-suricata.yaml")
        ));
    }

    for volume in SuricataContainer::new(context.clone()).volumes() {
        command.arg(format!("--volume={}", volume));
    }

    command.arg(context.image_name(Container::Suricata));
    command.args(["-v", "-i", interface]);
    command.args(["--include", "/config/evectl-suricata.yaml"]);

    for set_arg in set_args {
        command.args(["--set", &set_arg]);
    }

    if let Some(sensor_name) = &context.config.suricata.sensor_name {
        command.args(["--set", &format!("sensor-name={sensor_name}")]);
    }

    if let Some(bpf) = &context.config.suricata.bpf {
        command.arg(bpf);
    }

    Ok(command)
}

pub(crate) fn set_args(
    config: &[String],
    eve_output: EveOutput,
    fpc: &FpcConfig,
    file_extraction: &FileExtractionConfig,
) -> Result<Vec<String>> {
    let mut set_args: Vec<String> = vec![
        "app-layer.protocols.tls.ja4-fingerprints=true".to_string(),
        "app-layer.protocols.quic.ja4-fingerprints=true".to_string(),
    ];
    let mut eve_log_paths = BTreeSet::new();
    let mut pcap_log_paths = BTreeSet::new();
    let mut file_store_paths = BTreeSet::new();
    let mut disabled_output_paths = BTreeSet::new();
    let output_pattern = regex::Regex::new(r"^(outputs\.\d+) = ([a-zA-Z0-9_-]+)$")?;
    let patterns = &[
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.tls)\s")?,
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.quic)\s")?,
        regex::Regex::new(r"(outputs\.\d+\.eve-log\.types\.\d+\.dhcp)\s")?,
    ];
    for line in config {
        if let Some(c) = output_pattern.captures(line) {
            let path = format!("{}.{}", &c[1], &c[2]);
            if &c[2] == "eve-log" {
                eve_log_paths.insert(path);
            } else if &c[2] == "pcap-log" && fpc.enabled {
                pcap_log_paths.insert(path);
            } else if &c[2] == "file-store" && file_extraction.enabled {
                file_store_paths.insert(path);
            } else {
                disabled_output_paths.insert(path);
            }
        }

        for r in patterns {
            if let Some(c) = r.captures(line) {
                let path = &c[1];
                if path.ends_with(".dhcp") {
                    set_args.push(format!("{path}.extended=true"));
                } else {
                    set_args.push(format!("{path}.ja4=true"));
                }
            }
        }
    }
    for path in disabled_output_paths {
        set_args.push(format!("{path}.enabled=false"));
    }
    for path in eve_log_paths {
        set_args.push(format!("{path}.suricata-version=true"));
        set_args.push(format!("{path}.enabled=true"));
        if eve_output == EveOutput::UnixStream {
            set_args.push(format!("{path}.threaded=false"));
            set_args.push(format!("{path}.filetype=unix_stream"));
            set_args.push(format!("{path}.filename={EVE_SOCKET_CONTAINER_PATH}"));
        } else {
            // Timestamped spool files, rotated by Suricata and
            // deleted by EveBox once processed.
            set_args.push(format!("{path}.threaded=true"));
            set_args.push(format!("{path}.filename=eve.json.%s"));
            set_args.push(format!("{path}.rotate-interval=minute"));
        }
    }
    if fpc.enabled && pcap_log_paths.is_empty() {
        bail!("full packet capture enabled but Suricata has no pcap-log output");
    }
    for path in pcap_log_paths {
        // Layout expected by EveBox: multi mode with the rotation
        // timestamp in the filename so it can prune by time.
        set_args.push(format!("{path}.enabled=true"));
        set_args.push(format!("{path}.mode=multi"));
        set_args.push(format!("{path}.dir={PCAP_LOG_CONTAINER_DIR}"));
        set_args.push(format!("{path}.filename={PCAP_LOG_PREFIX}%n.%t.pcap"));
        set_args.push(format!("{path}.limit={}", FpcConfig::FILE_SIZE));
        set_args.push(format!(
            "{path}.max-files={}",
            fpc.max_files_per_thread(FpcConfig::capture_threads())
        ));
        set_args.push(format!("{path}.use-stream-depth=no"));
        set_args.push(format!("{path}.honor-pass-rules=no"));
    }
    if file_extraction.enabled {
        set_args.extend(file_extraction_set_args(
            config,
            file_extraction,
            &file_store_paths,
            FILESTORE_CONTAINER_DIR,
        )?);
    }
    Ok(set_args)
}

const HTTP_BODY_LIMITS: [&str; 2] = [
    "app-layer.protocols.http.libhtp.default-config.request-body-limit",
    "app-layer.protocols.http.libhtp.default-config.response-body-limit",
];

/// Overrides to enable the stock file-store output for file
/// extraction, raising the limits that would truncate files below the
/// max extract size. Limits are never lowered.
///
/// - Rule selected files: the file-store stream-depth applies to
///   sessions matching a filestore rule, and replaces the HTTP body
///   limits for them.
/// - Forced storage: the file-store stream-depth is never applied, so
///   the global stream depth and HTTP body limits are raised instead.
pub(crate) fn file_extraction_set_args(
    config: &[String],
    file_extraction: &FileExtractionConfig,
    file_store_paths: &BTreeSet<String>,
    directory: &str,
) -> Result<Vec<String>> {
    if file_store_paths.is_empty() {
        bail!("file extraction enabled but Suricata has no file-store output");
    }

    let max_size = file_extraction.max_size_bytes();
    let current = |key: &str| {
        let prefix = format!("{key} = ");
        config
            .iter()
            .find_map(|line| line.strip_prefix(&prefix))
            .and_then(FileExtractionConfig::parse_size)
    };
    // Unknown values are raised; 0 is unlimited.
    let below_max = |current: Option<u64>| current.is_none_or(|c| c != 0 && c < max_size);
    let stream_depth = current("stream.reassembly.depth");

    let mut set_args = vec![];
    for path in file_store_paths {
        set_args.push(format!("{path}.enabled=true"));
        set_args.push(format!("{path}.version=2"));
        set_args.push(format!("{path}.dir={directory}"));
        set_args.push(format!(
            "{path}.force-filestore={}",
            file_extraction.force_filestore
        ));
        // Redundant with the EVE fileinfo records.
        set_args.push(format!("{path}.write-fileinfo=false"));
        // Suricata ignores a file-store depth not above the global one.
        if !file_extraction.force_filestore && below_max(stream_depth) {
            set_args.push(format!("{path}.stream-depth={max_size}"));
        }
    }
    if file_extraction.force_filestore {
        if below_max(stream_depth) {
            set_args.push(format!("stream.reassembly.depth={max_size}"));
        }
        for key in HTTP_BODY_LIMITS {
            if below_max(current(key)) {
                set_args.push(format!("{key}={max_size}"));
            }
        }
    }
    Ok(set_args)
}

pub(crate) fn parse_version(text: &str) -> Option<Version> {
    let re = regex::Regex::new(
        r"(?i)\bSuricata(?:\s+version)?\s+([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\b",
    )
    .expect("valid Suricata version regex");
    let version = re.captures(text)?.get(1)?.as_str();
    Version::parse(version).ok()
}

/// Query the Suricata version. If the Suricata container is running,
/// the version is taken from the running container, otherwise a
/// throwaway container is run from the configured image.
pub(crate) fn version(context: &Context) -> Result<Option<Version>> {
    if context.manager.is_running(&container_name(context)) {
        running_version(context)
    } else {
        image_version(context)
    }
}

/// Query the version of Suricata in the running container.
pub(crate) fn running_version(context: &Context) -> Result<Option<Version>> {
    version_probe(context, ProbeTarget::Container(&container_name(context)))
}

/// Query the version of Suricata in the configured image by running
/// a throwaway container. Returns None if the image is not present,
/// as running it would trigger a pull.
pub(crate) fn image_version(context: &Context) -> Result<Option<Version>> {
    version_probe(
        context,
        ProbeTarget::Image(&context.image_name(Container::Suricata)),
    )
}

fn version_probe(context: &Context, target: ProbeTarget<'_>) -> Result<Option<Version>> {
    // The image entrypoint is suricata itself, while an exec needs
    // the program name.
    let args: &[&str] = match target {
        ProbeTarget::Container(_) => &["suricata", "-V"],
        ProbeTarget::Image(_) => &["-V"],
    };
    match context.manager.probe_command(target, args) {
        Some(command) => run_version_command(command),
        None => Ok(None),
    }
}

pub(crate) fn run_version_command(command: Command) -> Result<Option<Version>> {
    let (stdout, stderr) = crate::container::version_output(command, "Suricata")?;
    Ok(parse_version(&stdout).or_else(|| parse_version(&stderr)))
}

fn minimum_version() -> Version {
    Version::parse(MINIMUM_SURICATA_VERSION).expect("valid minimum Suricata version")
}

pub(crate) fn version_is_supported(version: &Version) -> bool {
    version >= &minimum_version()
}

pub(crate) fn warn_if_unsupported_version(context: &Context) {
    match version(context) {
        Ok(Some(version)) if !version_is_supported(&version) => warn!(
            "Suricata {version} is not supported; update the Suricata image to version {MINIMUM_SURICATA_VERSION} or newer"
        ),
        Ok(Some(version)) => debug!("Found Suricata version {version}"),
        Ok(None) => debug!("Could not determine the Suricata version"),
        Err(err) => debug!("Failed to determine the Suricata version: {err}"),
    }
}

pub(crate) fn dump_config(context: &Context) -> Result<Vec<String>> {
    let mut command = context.manager.command();
    command.arg("run");
    command.arg("--rm");
    command.arg(context.image_name(Container::Suricata));
    command.arg("--dump-config");
    let stdout = command
        .status_output()
        .context("Failed to run --dump-config for Suricata")?;
    let stdout = std::str::from_utf8(&stdout)?;
    Ok(stdout.lines().map(|s| s.to_string()).collect())
}

pub(crate) fn start_detached(context: &Context) -> Result<()> {
    crate::container::start_detached(context, &container_name(context), "Suricata", || {
        mkdirs(context)?;
        remove_engine_log(context);
        build_command(context, true)
    })?;

    if let Some(script) = eve_prune_script_for(context)
        && let Err(err) = start_eve_prune(context, &script)
    {
        error!("Failed to start EVE spool pruning: {err}");
    }

    Ok(())
}

/// EVE-only spool backstop. Extracted files are exclusively managed by
/// the housekeeping worker. EveBox normally deletes processed spool files;
/// retain the one-hour backstop for periods without a working consumer.
pub(crate) fn eve_prune_script_for(context: &Context) -> Option<String> {
    (context.config.suricata.eve_output == EveOutput::File).then(|| {
        "while true; do find /var/log/suricata -maxdepth 1 -name 'eve.json.*' ! -name '*.bookmark' -mmin +60 -delete; sleep 300; done".to_string()
    })
}

/// Start the EVE-only spool pruning loop in the Suricata container.
///
/// The loop is an exec'd process, so it does not survive a restart of
/// the container by the container runtime (restart policy); it is only
/// started again when EveCtl (re)starts Suricata.
pub(crate) fn start_eve_prune(context: &Context, script: &str) -> Result<()> {
    info!("Starting EVE spool pruning");
    context
        .manager
        .command()
        .args(["exec", "-d", &container_name(context), "bash", "-c", script])
        .status_output()?;
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::context::testing::docker_context;

    #[test]
    fn parses_and_checks_suricata_versions() {
        assert_eq!(
            parse_version("This is Suricata version 8.0.6 RELEASE"),
            Some(Version::new(8, 0, 6))
        );
        assert_eq!(
            parse_version("Suricata 9.0.0-dev"),
            Some(Version::parse("9.0.0-dev").unwrap())
        );
        // A packaging revision, as the Windows installer may report.
        assert_eq!(
            parse_version("Suricata version 8.0.6-1"),
            Some(Version::parse("8.0.6-1").unwrap())
        );
        assert_eq!(parse_version("unrecognized output"), None);

        assert!(!version_is_supported(&Version::parse("8.0.6-rc1").unwrap()));
        assert!(version_is_supported(&Version::new(8, 0, 6)));
        assert!(version_is_supported(&Version::new(9, 0, 0)));
    }

    #[test]
    fn suricata_output_overrides_disable_everything_except_eve_log() {
        let config = [
            "outputs.7 = fast",
            "outputs.7.fast.enabled = yes",
            "outputs.3 = eve-log",
            "outputs.3.eve-log.types.8.tls = (null)",
            "outputs.3.eve-log.types.32.stats = (null)",
            "outputs.12 = stats",
            "outputs.12.stats.enabled = yes",
            "outputs.14 = pcap-log",
            "outputs.14.pcap-log.enabled = no",
            "outputs.15 = file-store",
            "outputs.15.file-store.enabled = no",
            "logging.outputs.1.file.enabled = yes",
            "stream.reassembly.depth = 1 MiB",
            "app-layer.protocols.http.libhtp.default-config.request-body-limit = 100 KiB",
        ]
        .map(str::to_string);

        let set_args = set_args(
            &config,
            EveOutput::UnixStream,
            &FpcConfig::default(),
            &FileExtractionConfig::default(),
        )
        .unwrap();

        assert!(set_args.contains(&"outputs.7.fast.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.12.stats.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.15.file-store.enabled=false".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.enabled=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.suricata-version=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.threaded=false".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.filetype=unix_stream".to_string()));
        assert!(
            set_args.contains(&"outputs.3.eve-log.filename=/var/run/suricata/eve.sock".to_string())
        );
        assert!(set_args.contains(&"outputs.3.eve-log.types.8.tls.ja4=true".to_string()));
        assert_eq!(
            set_args
                .iter()
                .filter(|arg| arg.ends_with(".enabled=false"))
                .count(),
            4
        );
        assert!(!set_args.contains(&"outputs.3.eve-log.enabled=false".to_string()));
        assert!(!set_args.iter().any(|arg| arg.starts_with("logging.")));
        // Limits are only touched for file extraction.
        assert!(!set_args.iter().any(|arg| arg.starts_with("stream.")));
        assert!(!set_args.iter().any(|arg| arg.contains("body-limit")));
    }

    #[test]
    fn suricata_file_output_configures_timestamped_spool() {
        let config = ["outputs.3 = eve-log"].map(str::to_string);

        let set_args = set_args(
            &config,
            EveOutput::File,
            &FpcConfig::default(),
            &FileExtractionConfig::default(),
        )
        .unwrap();

        assert!(set_args.contains(&"outputs.3.eve-log.suricata-version=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.enabled=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.threaded=true".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.filename=eve.json.%s".to_string()));
        assert!(set_args.contains(&"outputs.3.eve-log.rotate-interval=minute".to_string()));
        assert!(!set_args.iter().any(|arg| arg.contains(".filetype=")));
    }

    #[test]
    fn fpc_configures_pcap_log_for_evebox() {
        let config = [
            "outputs.3 = eve-log",
            "outputs.14 = pcap-log",
            "outputs.14.pcap-log.enabled = no",
        ]
        .map(str::to_string);
        let fpc = FpcConfig {
            enabled: true,
            max_files: Some(20),
        };

        let set_args = set_args(
            &config,
            EveOutput::UnixStream,
            &fpc,
            &FileExtractionConfig::default(),
        )
        .unwrap();

        assert!(set_args.contains(&"outputs.14.pcap-log.enabled=true".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.mode=multi".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.dir=/var/log/suricata/pcap".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.filename=log.%n.%t.pcap".to_string()));
        assert!(set_args.contains(&"outputs.14.pcap-log.limit=256mb".to_string()));
        let expected = fpc.max_files_per_thread(FpcConfig::capture_threads());
        assert!(set_args.contains(&format!("outputs.14.pcap-log.max-files={expected}")));
        assert!(!set_args.contains(&"outputs.14.pcap-log.enabled=false".to_string()));

        // Without a pcap-log output in the dumped config, FPC can't be set up.
        let config = ["outputs.3 = eve-log"].map(str::to_string);
        assert!(
            super::set_args(
                &config,
                EveOutput::UnixStream,
                &fpc,
                &FileExtractionConfig::default()
            )
            .is_err()
        );
    }

    const MB: u64 = 1024 * 1024;

    fn file_extraction_args(file_extraction: FileExtractionConfig) -> Vec<String> {
        let config = [
            "outputs.1 = eve-log",
            "outputs.6 = file-store",
            "outputs.6.file-store.version = 2",
            "outputs.6.file-store.enabled = no",
            "stream.reassembly.depth = 1 MiB",
            "app-layer.protocols.http.libhtp.default-config.request-body-limit = 100 KiB",
            // Unlimited, must not be lowered.
            "app-layer.protocols.http.libhtp.default-config.response-body-limit = 0",
        ]
        .map(str::to_string);
        set_args(
            &config,
            EveOutput::UnixStream,
            &FpcConfig::default(),
            &FileExtractionConfig {
                enabled: true,
                ..file_extraction
            },
        )
        .unwrap()
    }

    fn has(set_args: &[String], arg: &str) -> bool {
        set_args.iter().any(|a| a == arg)
    }

    #[test]
    fn file_extraction_rule_selected_uses_file_store_depth() {
        let set_args = file_extraction_args(FileExtractionConfig::default());
        for expected in [
            "outputs.6.file-store.enabled=true",
            "outputs.6.file-store.version=2",
            "outputs.6.file-store.dir=/var/log/suricata/filestore",
            "outputs.6.file-store.force-filestore=false",
            "outputs.6.file-store.write-fileinfo=false",
            &format!("outputs.6.file-store.stream-depth={}", 4 * MB),
        ] {
            assert!(has(&set_args, expected), "missing {expected}");
        }
        assert!(!has(&set_args, "outputs.6.file-store.enabled=false"));
        assert!(!set_args.iter().any(|arg| arg.starts_with("stream.")));
        assert!(!set_args.iter().any(|arg| arg.contains("body-limit")));
    }

    #[test]
    fn file_extraction_forced_raises_global_limits() {
        let set_args = file_extraction_args(FileExtractionConfig {
            force_filestore: true,
            ..Default::default()
        });
        let max = 4 * MB;
        assert!(has(&set_args, "outputs.6.file-store.force-filestore=true"));
        assert!(has(&set_args, &format!("stream.reassembly.depth={max}")));
        assert!(has(
            &set_args,
            &format!("app-layer.protocols.http.libhtp.default-config.request-body-limit={max}")
        ));
        assert!(
            !set_args
                .iter()
                .any(|arg| arg.contains("response-body-limit"))
        );
        assert!(!set_args.iter().any(|arg| arg.contains("stream-depth")));
    }

    #[test]
    fn file_extraction_never_lowers_limits() {
        for force_filestore in [false, true] {
            let set_args = file_extraction_args(FileExtractionConfig {
                force_filestore,
                max_size: Some("512kb".to_string()),
                ..Default::default()
            });
            assert!(!set_args.iter().any(|arg| arg.contains("stream-depth")));
            assert!(!set_args.iter().any(|arg| arg.starts_with("stream.")));
        }
    }

    #[test]
    fn file_extraction_requires_file_store_output() {
        let config = ["outputs.1 = eve-log"].map(str::to_string);
        let file_extraction = FileExtractionConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(
            set_args(
                &config,
                EveOutput::UnixStream,
                &FpcConfig::default(),
                &file_extraction
            )
            .is_err()
        );
    }

    #[test]
    fn prune_script_only_covers_eve_spool() {
        let (_root, mut context) = docker_context(Config::default());
        for extraction in [false, true] {
            for retention in [None, Some(0), Some(19)] {
                context.config.suricata.file_extraction.enabled = extraction;
                context.config.suricata.file_extraction.max_age_days = retention;
                context.config.suricata.eve_output = EveOutput::UnixStream;
                assert_eq!(eve_prune_script_for(&context), None);
                context.config.suricata.eve_output = EveOutput::File;
                let eve = eve_prune_script_for(&context).unwrap();
                assert!(eve.starts_with(
                    "while true; do find /var/log/suricata -maxdepth 1 -name 'eve.json.*'"
                ));
                assert!(eve.contains("! -name '*.bookmark' -mmin +60 -delete"));
                assert!(eve.ends_with("; sleep 300; done"));
                assert!(!eve.contains("filestore"));
                assert!(!eve.contains("suricatactl"));
            }
        }
    }

    #[test]
    fn host_directories_share_the_log_root() {
        let (_root, context) = docker_context(Config::default());
        let log_dir = log_dir(&context);
        assert_eq!(log_dir, context.data_dir().join("suricata").join("log"));
        assert_eq!(pcap_dir(&context), log_dir.join("pcap"));
        assert_eq!(filestore_dir(&context), log_dir.join("filestore"));
        assert_eq!(
            run_dir(&context),
            context.data_dir().join("suricata").join("run")
        );
        assert_eq!(
            lib_dir(&context),
            context.config_dir().join("suricata").join("lib")
        );
    }
}
