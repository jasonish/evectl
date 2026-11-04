// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Suricata rule management through suricatax-rules.

use super::paths::{Paths, load_evectl_config};
use super::platform::WindowsPlatform;
use super::service::{self, Control};
use super::stack::capture_restart_plan;
use super::suricata::{
    SURICATA_VERSION, find_suricata_executable, start_suricata_service, stop_suricata,
    suricata_installed_version,
};
use crate::prelude::*;
use semver::Version;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use suricatax_rules::cli as suricatax_cli;
use suricatax_rules::paths::PathProvider;

/// How long Suricata has to reload its rules.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(120);
const RELOAD_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub(super) struct EvectlWindowsPaths {
    sources_dir: PathBuf,
    cache_dir: PathBuf,
    pub(super) rules_dir: PathBuf,
}

impl PathProvider for EvectlWindowsPaths {
    fn sources_dir(&self) -> PathBuf {
        self.sources_dir.clone()
    }

    fn cache_dir(&self) -> PathBuf {
        self.cache_dir.clone()
    }

    fn rules_dir(&self) -> PathBuf {
        self.rules_dir.clone()
    }
}

pub(super) fn suricatax_paths(paths: &Paths) -> EvectlWindowsPaths {
    EvectlWindowsPaths {
        sources_dir: paths.suricata_update_dir().join("sources"),
        cache_dir: paths.suricata_update_dir().join("cache"),
        rules_dir: paths.suricata_rules_dir(),
    }
}

fn with_path_provider<T>(
    paths: &Paths,
    f: impl FnOnce(&dyn PathProvider) -> Result<T>,
) -> Result<T> {
    let provider = suricatax_paths(paths);
    f(&provider)
}

pub(super) fn update_rules(paths: &Paths, force: bool, quiet: bool) -> Result<()> {
    let suricata_version = detect_suricata_version_for_rules_update(paths);

    if let Some(version) = &suricata_version {
        info!("Selecting rules for Suricata version {}", version);
    } else {
        warn!(
            "Could not determine Suricata version for rules update; using suricatax-rules default"
        );
    }

    // The updater always rewrites its output, so compare a digest
    // of the rules directory before and after to tell whether the
    // rules actually changed.
    let rules_dir = paths.suricata_rules_dir();
    let before = rules_digest(&rules_dir)?;

    with_path_provider(paths, |paths| {
        suricatax_cli::update_rules_with_options(
            paths,
            force,
            quiet,
            suricata_version.as_deref(),
            &[],
            &[],
        )
    })?;

    if rules_digest(&rules_dir)? == before {
        info!("Rules unchanged, Suricata does not need to reload them");
        return Ok(());
    }

    reload_rules(paths)
}

/// Have a running Suricata load the current rules: with the reload
/// control when its service supports it, otherwise by restarting it.
pub(super) fn reload_rules(paths: &Paths) -> Result<()> {
    if reload_service_rules(paths)? {
        return Ok(());
    }
    restart_suricata_for_rules(paths)
}

/// Have a running Suricata service reload its rules, waiting for it to
/// finish. False if the service isn't running or can't reload rules.
fn reload_service_rules(paths: &Paths) -> Result<bool> {
    if !service::is_running(paths)? {
        return Ok(false);
    }
    // The reload's outcome is logged after where the log ends now.
    let log = paths.suricata_log_file();
    let offset = std::fs::metadata(&log).map(|metadata| metadata.len());
    if !service::control(paths, Control::ReloadRules)? {
        info!("The installed Suricata can't reload rules as a service");
        return Ok(false);
    }
    info!("Asked the Suricata service to reload its rules");
    if let Ok(offset) = offset {
        wait_for_reload(&log, offset)?;
    }
    Ok(true)
}

/// Wait for Suricata to log that it finished reloading its rules, past
/// `offset` in its log. A failed reload logs no outcome, so it's
/// reported once the reload doesn't finish in time.
fn wait_for_reload(log: &Path, offset: u64) -> Result<()> {
    let deadline = Instant::now() + RELOAD_TIMEOUT;
    loop {
        match reload_progress(&read_log_from(log, offset)?) {
            Reload::Complete { summary } => {
                match summary {
                    Some(summary) => info!("Suricata reloaded its rules: {summary}"),
                    None => info!("Suricata reloaded its rules"),
                }
                return Ok(());
            }
            Reload::Pending { errors } if Instant::now() >= deadline => {
                let mut message = format!(
                    "Suricata did not finish reloading its rules within {} seconds, see {}",
                    RELOAD_TIMEOUT.as_secs(),
                    log.display()
                );
                for error in &errors[errors.len().saturating_sub(5)..] {
                    message.push_str("\n  ");
                    message.push_str(error);
                }
                bail!(message);
            }
            Reload::Pending { .. } => std::thread::sleep(RELOAD_POLL_INTERVAL),
        }
    }
}

/// The log from `offset`, or all of it if it has been rotated since.
fn read_log_from(path: &Path, offset: u64) -> Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    if file.metadata()?.len() >= offset {
        file.seek(SeekFrom::Start(offset))?;
    }
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// A rule reload's progress, as logged by Suricata.
#[derive(Debug, PartialEq)]
enum Reload {
    /// Not finished, with the errors logged since it started.
    Pending { errors: Vec<String> },
    /// Finished, with Suricata's summary of the rules loaded.
    Complete { summary: Option<String> },
}

/// The progress of the first rule reload in Suricata's log.
fn reload_progress(log: &str) -> Reload {
    let mut started = false;
    let mut summary = None;
    let mut errors = vec![];
    for line in log.lines() {
        if line.contains("rule reload starting") {
            started = true;
            summary = None;
            errors.clear();
        } else if !started {
            continue;
        } else if line.contains("rule reload complete") {
            return Reload::Complete { summary };
        } else if line.contains("rules successfully loaded") {
            // A reload logs the summary for the default tenant.
            let message = log_message(line);
            let message = message.strip_prefix("tenant id 0:").unwrap_or(message);
            summary = Some(message.trim_start().to_string());
        } else if line.contains(" Error: ") {
            errors.push(log_message(line).to_string());
        }
    }
    Reload::Pending { errors }
}

/// The message of a Suricata log line, without the process, thread,
/// time, level, and module before it.
fn log_message(line: &str) -> &str {
    line.splitn(3, ": ").nth(2).unwrap_or(line)
}

/// A digest of every file under the rules directory (the rules
/// file and any dataset files), or None if it doesn't exist yet.
fn rules_digest(rules_dir: &Path) -> Result<Option<String>> {
    use sha2::{Digest, Sha256};

    fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in
            std::fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))?
        {
            let path = entry?.path();
            if path.is_dir() {
                collect(&path, files)?;
            } else {
                files.push(path);
            }
        }
        Ok(())
    }

    if !rules_dir.exists() {
        return Ok(None);
    }

    let mut files = vec![];
    collect(rules_dir, &mut files)?;
    files.sort();

    let mut hash = Sha256::new();
    for path in files {
        let relative = path.strip_prefix(rules_dir).unwrap_or(&path);
        hash.update(relative.to_string_lossy().as_bytes());
        hash.update([0]);
        hash.update(
            std::fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))?,
        );
        hash.update([0]);
    }
    Ok(Some(
        hash.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

/// Restart Suricata, if running, to load the rules.
fn restart_suricata_for_rules(paths: &Paths) -> Result<()> {
    let plan = capture_restart_plan(paths)?;
    if !plan.suricata_running {
        info!("Suricata is not running; the rules load when it starts");
        return Ok(());
    }
    let guid = plan.suricata_guid.as_deref().ok_or_else(|| {
        anyhow!("Failed to determine the interface GUID used by the running Suricata process")
    })?;

    info!("Restarting Suricata to load the rules");
    let result = (|| {
        stop_suricata(paths)?;
        start_suricata_service(paths, &load_evectl_config(paths)?, guid).map(|_| ())
    })();
    result.map_err(|err| anyhow!("Restarting Suricata to load the rules failed: {}", err))
}

/// The version used to select rules: the running executable's, else
/// the installed marker's, else the bundled installer's.
fn detect_suricata_version_for_rules_update(paths: &Paths) -> Option<String> {
    let installed = || match suricata_installed_version(paths) {
        Ok(Some(version)) => Version::parse(&version).ok(),
        Ok(None) => None,
        Err(err) => {
            warn!(
                "Failed to determine installed Suricata version for rules update: {}",
                err
            );
            None
        }
    };
    suricata_runtime_version(paths)
        .or_else(installed)
        .or_else(|| Version::parse(SURICATA_VERSION).ok())
        .map(|version| release_version(&version))
}

fn suricata_runtime_version(paths: &Paths) -> Option<Version> {
    let mut command = Command::new(find_suricata_executable(paths)?);
    command.arg("-V");
    crate::suricata::run_version_command(command).ok().flatten()
}

/// Rule sources are selected by release, without any pre-release or
/// build suffix.
fn release_version(version: &Version) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}

pub(super) fn update_sources(paths: &Paths) -> Result<()> {
    with_path_provider(paths, suricatax_cli::update_sources)
}

pub(super) fn enable_ruleset(paths: &Paths, name: Option<&str>) -> Result<()> {
    match name {
        Some(name) => with_path_provider(paths, |paths| suricatax_cli::enable_ruleset(paths, name)),
        None => crate::menu::rules::enable_ruleset(&WindowsPlatform { paths }),
    }
}

pub(super) fn add_custom_ruleset(paths: &Paths, name: &str, url: &str) -> Result<()> {
    with_path_provider(paths, |paths| {
        suricatax_cli::add_custom_ruleset(paths, name, url)
    })
}

pub(super) fn disable_ruleset(paths: &Paths, name: &str) -> Result<()> {
    with_path_provider(paths, |paths| suricatax_cli::disable_ruleset(paths, name))
}

pub(super) fn list_enabled_rulesets(paths: &Paths) -> Result<()> {
    crate::menu::rules::list_enabled_rulesets(&WindowsPlatform { paths })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_progress_reports_the_first_reload() {
        let line = |level: &str, module: &str, message: &str| {
            format!("[11880 - Suricata-Main] 2026-10-13 00:42:55 {level}: {module}: {message}\n")
        };
        let summary = "1 rule files processed. 52608 rules successfully loaded, 2 rules failed, 0 rules skipped";
        let error = r#"error parsing signature "alert x" from file rules\suricata.rules at line 7"#;

        let mut log = line(
            "Notice",
            "suricata",
            "Rule reload requested by service control",
        );
        assert_eq!(reload_progress(&log), Reload::Pending { errors: vec![] });

        log += &line("Notice", "detect", "rule reload starting");
        log += &line("Error", "detect", error);
        log += &line("Info", "detect", &format!("tenant id 0:  {summary}"));
        assert_eq!(
            reload_progress(&log),
            Reload::Pending {
                errors: vec![error.to_string()]
            }
        );

        log += &line("Notice", "detect", "rule reload complete");
        let complete = Reload::Complete {
            summary: Some(summary.to_string()),
        };
        assert_eq!(reload_progress(&log), complete);

        // The first reload after the request is the one reported.
        log += &line("Notice", "detect", "rule reload starting");
        assert_eq!(reload_progress(&log), complete);
    }

    #[test]
    fn rules_digest_tracks_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        let rules_dir = dir.path().join("rules");
        assert_eq!(rules_digest(&rules_dir).unwrap(), None);

        std::fs::create_dir_all(rules_dir.join("datasets")).unwrap();
        std::fs::write(
            rules_dir.join("suricata.rules"),
            "alert ip any any -> any any (sid:1;)\n",
        )
        .unwrap();
        std::fs::write(rules_dir.join("datasets").join("a.lst"), "one\n").unwrap();
        let first = rules_digest(&rules_dir).unwrap();
        assert!(first.is_some());

        // Rewriting identical content is not a change.
        std::fs::write(
            rules_dir.join("suricata.rules"),
            "alert ip any any -> any any (sid:1;)\n",
        )
        .unwrap();
        assert_eq!(rules_digest(&rules_dir).unwrap(), first);

        // A dataset change counts, as does a rules change.
        std::fs::write(rules_dir.join("datasets").join("a.lst"), "two\n").unwrap();
        let second = rules_digest(&rules_dir).unwrap();
        assert_ne!(second, first);
        std::fs::write(rules_dir.join("suricata.rules"), "").unwrap();
        assert_ne!(rules_digest(&rules_dir).unwrap(), second);
    }
}
