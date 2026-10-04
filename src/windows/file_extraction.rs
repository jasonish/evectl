// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Native Windows file extraction and age-based filestore retention.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use crate::config::FileExtractionConfig;
use crate::prelude::*;

// Only used by the Windows housekeeper loop; this module also builds on
// Linux for its tests.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(240);

pub(super) fn enabled(config: &Config) -> bool {
    config.suricata.enabled && config.suricata.file_extraction.enabled
}

pub(super) fn cleanup_enabled(config: &Config) -> bool {
    enabled(config) && config.suricata.file_extraction.max_age_days() > 0
}

pub(super) fn configure_evebox_command(command: &mut Command, config: &Config, directory: &Path) {
    if enabled(config) {
        command.arg("--filestore-directory").arg(directory);
    }
}

/// Reuse Linux's limit handling, discovering output indexes from the installed config.
/// Disabled extraction overrides any file-store enabled in the installed YAML.
pub(super) fn configure_command(
    command: &mut Command,
    dump: &str,
    config: &FileExtractionConfig,
    directory: &Path,
) -> Result<()> {
    let pattern = regex::Regex::new(r"^(outputs\.\d+) = file-store$")?;
    let lines: Vec<String> = dump.lines().map(|line| line.trim().to_string()).collect();
    let paths: BTreeSet<String> = lines
        .iter()
        .filter_map(|line| pattern.captures(line))
        .map(|c| format!("{}.file-store", &c[1]))
        .collect();
    let overrides = if config.enabled {
        crate::suricata::file_extraction_set_args(
            &lines,
            config,
            &paths,
            &directory.to_string_lossy().replace('\\', "/"),
        )?
    } else {
        paths
            .iter()
            .map(|path| format!("{path}.enabled=false"))
            .collect()
    };
    for setting in overrides {
        command.arg("--set").arg(setting);
    }
    Ok(())
}

/// Do not traverse symlinks or Windows junctions/reparse points outside the filestore.
fn linked(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(not(windows))]
    {
        metadata.is_symlink()
    }
}

/// Prune the entire filestore (including tmp), by modification time like Linux.
/// Missing directories are normal before Suricata creates the filestore. Per-file
/// failures are logged and retried next time; never follow links or remove directories.
pub(super) fn prune(directory: &Path, retention_days: u32, now: SystemTime) -> Result<u64> {
    if retention_days == 0 {
        return Ok(0);
    }
    let cutoff = now
        .checked_sub(Duration::from_secs(u64::from(retention_days) * 86400))
        .context("Filestore retention predates the system clock")?;
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    let mut pending = vec![directory.to_path_buf()];
    let mut removed = 0;
    while let Some(dir) = pending.pop() {
        if Instant::now() >= deadline {
            bail!("Filestore cleanup exceeded its four-minute timeout");
        }
        let metadata = match std::fs::symlink_metadata(&dir) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                warn!("Cannot inspect {}: {err}", dir.display());
                continue;
            }
        };
        if linked(&metadata) || !metadata.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                warn!("Cannot read {}: {err}", dir.display());
                continue;
            }
        };
        for entry in entries {
            if Instant::now() >= deadline {
                bail!("Filestore cleanup exceeded its four-minute timeout");
            }
            let result = (|| -> Result<()> {
                let path = entry?.path();
                let metadata = match std::fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(err) => {
                        return Err(err)
                            .with_context(|| format!("Cannot inspect {}", path.display()));
                    }
                };
                if linked(&metadata) {
                    return Ok(());
                }
                if metadata.is_dir() {
                    pending.push(path);
                } else if metadata.is_file() && metadata.modified()? < cutoff {
                    match std::fs::remove_file(&path) {
                        Ok(()) => removed += 1,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => {
                            return Err(err)
                                .with_context(|| format!("Cannot delete {}", path.display()));
                        }
                    }
                }
                Ok(())
            })();
            if let Err(err) = result {
                warn!("Filestore cleanup: {err:#}");
            }
        }
    }
    Ok(removed)
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

    const DUMP: &str = "outputs.0 = eve-log\noutputs.17 = file-store\noutputs.18 = pcap-log\n\
        outputs.17.file-store.enabled = no\nstream.reassembly.depth = 1 MiB\n\
        app-layer.protocols.http.libhtp.default-config.request-body-limit = 100 KiB\n\
        app-layer.protocols.http.libhtp.default-config.response-body-limit = 0\n";

    #[test]
    fn windows_uses_linux_overrides_with_native_filestore_path() {
        for force_filestore in [false, true] {
            let extraction = FileExtractionConfig {
                enabled: true,
                force_filestore,
                ..Default::default()
            };
            let mut command = Command::new("suricata.exe");
            configure_command(
                &mut command,
                DUMP,
                &extraction,
                Path::new(r"C:\Users\Test User\evectl\suricata\log\filestore"),
            )
            .unwrap();
            let lines: Vec<String> = DUMP.lines().map(str::to_string).collect();
            let expected = crate::suricata::file_extraction_set_args(
                &lines,
                &extraction,
                &BTreeSet::from(["outputs.17.file-store".into()]),
                "C:/Users/Test User/evectl/suricata/log/filestore",
            )
            .unwrap();
            let actual = args(&command);
            assert_eq!(actual.len(), expected.len() * 2);
            for (pair, setting) in actual.as_chunks::<2>().0.iter().zip(&expected) {
                assert_eq!(pair[0], "--set");
                assert_eq!(&pair[1], setting);
            }
            assert!(actual.contains(&"outputs.17.file-store.version=2".into()));
            assert!(actual.contains(&"outputs.17.file-store.write-fileinfo=false".into()));
            let limit = 4 * 1024 * 1024;
            if force_filestore {
                assert!(actual.contains(&format!("stream.reassembly.depth={limit}")));
                assert!(
                    actual
                        .iter()
                        .any(|arg| arg.ends_with(&format!("request-body-limit={limit}")))
                );
                assert!(!actual.iter().any(|arg| arg.contains("response-body-limit")));
            } else {
                assert!(actual.contains(&format!("outputs.17.file-store.stream-depth={limit}")));
                assert!(!actual.iter().any(|arg| arg.contains("body-limit")));
            }
        }
    }

    #[test]
    fn disabled_extraction_only_disables_filestore_and_missing_output_is_checked() {
        let mut command = Command::new("suricata.exe");
        configure_command(
            &mut command,
            &format!("{DUMP}outputs.25 = file-store\n"),
            &FileExtractionConfig::default(),
            Path::new("unused"),
        )
        .unwrap();
        assert_eq!(
            args(&command),
            [
                "--set",
                "outputs.17.file-store.enabled=false",
                "--set",
                "outputs.25.file-store.enabled=false"
            ]
        );
        for enabled in [false, true] {
            let mut command = Command::new("suricata.exe");
            let result = configure_command(
                &mut command,
                "outputs.0 = eve-log\n",
                &FileExtractionConfig {
                    enabled,
                    ..Default::default()
                },
                Path::new("filestore"),
            );
            assert_eq!(result.is_err(), enabled);
            assert!(args(&command).is_empty());
        }
    }

    #[test]
    fn extraction_never_lowers_limits() {
        for depth in ["0", "16 MiB"] {
            for force_filestore in [false, true] {
                let mut command = Command::new("suricata.exe");
                let dump = format!(
                    "outputs.2 = file-store\nstream.reassembly.depth = {depth}\n\
                    app-layer.protocols.http.libhtp.default-config.request-body-limit = {depth}\n\
                    app-layer.protocols.http.libhtp.default-config.response-body-limit = {depth}\n"
                );
                configure_command(
                    &mut command,
                    &dump,
                    &FileExtractionConfig {
                        enabled: true,
                        force_filestore,
                        ..Default::default()
                    },
                    Path::new("filestore"),
                )
                .unwrap();
                assert!(
                    !args(&command).iter().any(|arg| arg.contains("stream-depth")
                        || arg.starts_with("stream.")
                        || arg.contains("body-limit"))
                );
            }
        }
    }

    #[test]
    fn retrieval_and_agent_credentials_are_independent_of_packet_capture() {
        let directory = Path::new(r"C:\Users\Test User\suricata\log\filestore");
        for suricata in [false, true] {
            for extraction in [false, true] {
                for capture in [false, true] {
                    for retention in [0, 7] {
                        let mut config = Config::default();
                        config.suricata.enabled = suricata;
                        config.suricata.file_extraction.enabled = extraction;
                        config.suricata.file_extraction.max_age_days = Some(retention);
                        config.fpc.enabled = capture;
                        config.evebox_agent.enabled = true;
                        config.evebox_agent.agent_id = Some("sensor".into());
                        config.evebox_agent.key = Some("secret-key".into());
                        assert_eq!(
                            cleanup_enabled(&config),
                            suricata && extraction && retention > 0
                        );
                        let mut server = Command::new("evebox.exe");
                        configure_evebox_command(&mut server, &config, directory);
                        let expected = if suricata && extraction {
                            vec!["--filestore-directory", directory.to_str().unwrap()]
                        } else {
                            vec![]
                        };
                        assert_eq!(args(&server), expected);
                        let mut agent = Command::new("evebox.exe");
                        super::super::fpc::configure_agent_command(
                            &mut agent,
                            &config,
                            Path::new("pcap"),
                        );
                        configure_evebox_command(&mut agent, &config, directory);
                        let actual = args(&agent);
                        assert_eq!(
                            actual.iter().any(|arg| arg == "--filestore-directory"),
                            suricata && extraction
                        );
                        assert_eq!(
                            actual.iter().any(|arg| arg == "--pcap-directory"),
                            suricata && capture
                        );
                        assert_eq!(&actual[..2], ["--agent-id", "sensor"]);
                        assert!(!actual.iter().any(|arg| arg.contains("secret-key")));
                        assert_eq!(
                            agent.get_envs().count(),
                            usize::from(suricata && (capture || extraction))
                        );
                    }
                }
            }
        }
    }

    fn write_at(path: &Path, modified: SystemTime) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::File::create(path).unwrap();
        file.set_modified(modified).unwrap();
    }

    #[test]
    fn retention_prunes_old_files_including_tmp_and_keeps_recent_files() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let old = now - Duration::from_secs(8 * 86400);
        let filestore = dir.path().join("filestore");
        assert_eq!(prune(&filestore, 7, now).unwrap(), 0);
        write_at(&filestore.join("ab/old"), old);
        write_at(&filestore.join("tmp/old"), old);
        write_at(&filestore.join("ab/recent"), now);
        write_at(&filestore.join("tmp/recent"), now);
        write_at(&dir.path().join("eve.json"), old);
        assert_eq!(prune(&filestore, 0, now).unwrap(), 0);
        assert_eq!(prune(&filestore, 7, now).unwrap(), 2);
        assert!(!filestore.join("ab/old").exists());
        assert!(!filestore.join("tmp/old").exists());
        assert!(filestore.join("ab/recent").exists());
        assert!(filestore.join("tmp/recent").exists());
        assert!(dir.path().join("eve.json").exists());
    }

    #[cfg(windows)]
    #[test]
    fn retention_does_not_follow_junctions_including_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let filestore = dir.path().join("filestore");
        let outside = dir.path().join("outside");
        let now = SystemTime::now();
        write_at(&outside.join("old"), now - Duration::from_secs(8 * 86400));
        std::fs::create_dir(&filestore).unwrap();
        for link in [filestore.join("linked"), dir.path().join("root-link")] {
            let output = Command::new("cmd.exe")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&outside)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(prune(&filestore, 7, now).unwrap(), 0);
        assert_eq!(prune(&dir.path().join("root-link"), 7, now).unwrap(), 0);
        assert!(outside.join("old").exists());
    }

    #[cfg(unix)]
    #[test]
    fn retention_does_not_follow_links_including_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let filestore = dir.path().join("filestore");
        let outside = dir.path().join("outside");
        let now = SystemTime::now();
        write_at(&outside.join("old"), now - Duration::from_secs(8 * 86400));
        std::fs::create_dir(&filestore).unwrap();
        std::os::unix::fs::symlink(&outside, filestore.join("linked")).unwrap();
        assert_eq!(prune(&filestore, 7, now).unwrap(), 0);
        let root = dir.path().join("root-link");
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        assert_eq!(prune(&root, 7, now).unwrap(), 0);
        assert!(outside.join("old").exists());
    }
}
