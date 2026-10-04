// SPDX-FileCopyrightText: (C) 2026 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

//! Suricata rule management through suricatax-rules.

use super::paths::get_suricata_data_dir;
use super::stack::capture_restart_plan;
use super::suricata::{
    find_suricata_executable, get_suricata_installed_version, start_suricata_background,
    stop_suricata_managed, suricata_version_for_comparison, wait_for_suricata_readiness,
};
use super::version::parse_version_parts;
use crate::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use suricatax_rules::cli as suricatax_cli;
use suricatax_rules::paths::PathProvider;
use suricatax_rules::sources::SourceManager;

const WINDOWS_UNSUPPORTED_RULE_SUBSTRINGS: [&str; 1] = ["file.magic"];

pub(super) struct WindowsRulesBackend;

impl crate::rules::Backend for WindowsRulesBackend {
    fn available_rulesets(&self) -> Result<Vec<crate::rules::Ruleset>> {
        let paths = get_suricatax_paths()?;
        Ok(SourceManager::new(&paths)
            .get_or_download_index()?
            .sources
            .into_iter()
            .map(|(id, source)| crate::rules::Ruleset {
                id,
                summary: Some(source.summary),
                can_enable: source.obsolete.is_none() && source.parameters.is_none(),
            })
            .collect())
    }

    fn enabled_rulesets(&self) -> Result<Vec<crate::rules::Ruleset>> {
        let paths = get_suricatax_paths()?;
        let enabled = suricatax_cli::enabled_rulesets(&paths)?;
        if enabled.is_empty() {
            return Ok(vec![]);
        }
        let index = SourceManager::new(&paths)
            .read_local_index()
            .unwrap_or(None);
        Ok(enabled
            .into_iter()
            .map(|id| {
                let summary = index
                    .as_ref()
                    .and_then(|index| index.sources.get(&id))
                    .map(|source| source.summary.clone());
                crate::rules::Ruleset {
                    id,
                    summary,
                    can_enable: false,
                }
            })
            .collect())
    }

    fn enable_ruleset(&self, id: &str) -> Result<()> {
        enable_ruleset(Some(id))
    }

    fn disable_ruleset(&self, id: &str) -> Result<()> {
        disable_ruleset(id)
    }

    fn update_sources(&self) -> Result<()> {
        update_sources()
    }

    fn update_rules(&self) -> Result<()> {
        update_rules(false, false)
    }
}

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

pub(super) fn get_suricatax_paths() -> Result<EvectlWindowsPaths> {
    let lib_dir = get_suricata_data_dir()?.join("lib");
    Ok(EvectlWindowsPaths {
        sources_dir: lib_dir.join("update").join("sources"),
        cache_dir: lib_dir.join("update").join("cache"),
        rules_dir: lib_dir.join("rules"),
    })
}

fn with_path_provider<T>(f: impl FnOnce(&dyn PathProvider) -> Result<T>) -> Result<T> {
    let paths = get_suricatax_paths()?;
    f(&paths)
}

pub(super) fn update_rules(force: bool, quiet: bool) -> Result<()> {
    let suricata_version = detect_suricata_version_for_rules_update();
    let disable_substrings = WINDOWS_UNSUPPORTED_RULE_SUBSTRINGS
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();

    if let Some(version) = &suricata_version {
        info!("Selecting rules for Suricata version {}", version);
    } else {
        warn!(
            "Could not determine Suricata version for rules update; using suricatax-rules default"
        );
    }

    if !disable_substrings.is_empty() {
        info!(
            "Disabling rules containing unsupported Suricata for Windows keywords: {}",
            disable_substrings.join(", ")
        );
    }

    // The updater always rewrites its output, so compare a digest
    // of the rules directory before and after to tell whether the
    // rules actually changed.
    let rules_dir = get_suricatax_paths()?.rules_dir;
    let before = rules_digest(&rules_dir)?;

    with_path_provider(|paths| {
        suricatax_cli::update_rules_with_options(
            paths,
            force,
            quiet,
            suricata_version.as_deref(),
            &[],
            &disable_substrings,
        )
    })?;

    if rules_digest(&rules_dir)? == before {
        info!("Rules unchanged, Suricata does not need to be restarted");
        return Ok(());
    }

    restart_suricata_for_rules()
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

/// Suricata on Windows can't reload rules in place, so restart it,
/// if running, to load the updated rules.
fn restart_suricata_for_rules() -> Result<()> {
    let plan = capture_restart_plan()?;
    if !plan.suricata_running {
        return Ok(());
    }
    let guid = plan.suricata_guid.as_deref().ok_or_else(|| {
        anyhow!("Failed to determine the interface GUID used by the running Suricata process")
    })?;

    info!("Restarting Suricata to load the updated rules");
    let result = (|| {
        stop_suricata_managed()?;
        let suricata = start_suricata_background(guid)?;
        wait_for_suricata_readiness(&suricata)
    })();
    result.map_err(|err| anyhow!("Rules updated, but restarting Suricata failed: {}", err))
}

fn detect_suricata_version_for_rules_update() -> Option<String> {
    if let Some(version) = get_suricata_runtime_version() {
        return Some(version);
    }

    match get_suricata_installed_version() {
        Ok(Some(version)) => normalize_suricata_version(&version)
            .or_else(|| normalize_suricata_version(suricata_version_for_comparison())),
        Ok(None) => normalize_suricata_version(suricata_version_for_comparison()),
        Err(err) => {
            warn!(
                "Failed to determine installed Suricata version for rules update: {}",
                err
            );
            normalize_suricata_version(suricata_version_for_comparison())
        }
    }
}

fn get_suricata_runtime_version() -> Option<String> {
    let suricata_path = find_suricata_executable()?;
    let output = Command::new(&suricata_path).arg("-V").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(version) = parse_suricata_version_from_text(&stdout) {
        return Some(version);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_suricata_version_from_text(&stderr)
}

fn parse_suricata_version_from_text(text: &str) -> Option<String> {
    use std::sync::LazyLock;

    static VERSION_HINT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\b(?:suricata\s+)?version\s+([0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?)\b",
        )
        .expect("hardcoded regex is valid")
    });
    static SEMVER_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\b([0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?)\b")
            .expect("hardcoded regex is valid")
    });

    if let Some(caps) = VERSION_HINT_RE.captures(text)
        && let Some(candidate) = caps.get(1)
        && let Some(version) = normalize_suricata_version(candidate.as_str())
    {
        return Some(version);
    }

    for caps in SEMVER_RE.captures_iter(text) {
        if let Some(candidate) = caps.get(1)
            && let Some(version) = normalize_suricata_version(candidate.as_str())
        {
            return Some(version);
        }
    }

    None
}

fn normalize_suricata_version(version: &str) -> Option<String> {
    let candidate = version
        .trim()
        .trim_matches(['"', '\''])
        .split_whitespace()
        .next()
        .unwrap_or("")
        .split('-')
        .next()
        .unwrap_or("")
        .trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');

    if parse_version_parts(candidate).is_some() {
        Some(candidate.to_string())
    } else {
        None
    }
}

pub(super) fn update_sources() -> Result<()> {
    with_path_provider(suricatax_cli::update_sources)
}

pub(super) fn enable_ruleset(name: Option<&str>) -> Result<()> {
    match name {
        Some(name) => with_path_provider(|paths| suricatax_cli::enable_ruleset(paths, name)),
        None => crate::menu::rules::enable_ruleset(&WindowsRulesBackend),
    }
}

pub(super) fn disable_ruleset(name: &str) -> Result<()> {
    with_path_provider(|paths| suricatax_cli::disable_ruleset(paths, name))
}

pub(super) fn list_enabled_rulesets() -> Result<()> {
    crate::menu::rules::list_enabled_rulesets(&WindowsRulesBackend)
}

#[cfg(test)]
mod tests {
    use super::*;

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
